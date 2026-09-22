# NAPQES for Database Backups — Encryption, Integrity, and Disaster Recovery

Written for: DBAs, backup engineers, and platform SREs evaluating NAPQES as the
at-rest encryption layer for large database backups.

This document answers three operational questions:

1. How NAPQES encrypts and decrypts large data (e.g. database backups) at scale.
2. How the AEAD construction prevents undetected data corruption.
3. How to structure backups and disaster recovery when NAPQES is the at-rest
   cipher for those backups.

Normative wire-format details are in [SPEC.md](../SPEC.md); this document
summarises the operational picture and cites SPEC sections for depth.

---

## 1. Encryption and decryption at scale (large data / DB backups)

For any input that will not fit comfortably in memory — a full `pg_dump`, an
Oracle RMAN piece, an S3-scale bucket snapshot — the caller MUST use the
**v8 streaming AE format** ([SPEC.md §8.2](../SPEC.md)). Block mode
([SPEC.md §5](../SPEC.md)) has a 65 535-codepoint length cap and is not
appropriate for backup-sized inputs.

### 1.1 High-level dataflow

```mermaid
flowchart LR
    DB[(Source database)] -->|pg_dump / RMAN / mongodump| PLAIN[Plaintext backup stream]
    PLAIN --> CHUNK[Split into fixed F-codepoint chunks]
    CHUNK --> ENC[NAPQES v8 stream encryptor]
    KMS[(KMS / HSM<br/>holds NAPQES key)] -->|sk = key material| ENC
    RNG[[CSPRNG]] -->|16-byte nonce per stream| ENC
    ENC --> HEADER[Header: 0x02 or F or nonce]
    ENC --> FRAMES[Chunk frames: len or masked or tag]
    ENC --> SENT[Sentinel: 0x00 or count or tag]
    HEADER --> WRITER[Object writer]
    FRAMES --> WRITER
    SENT --> WRITER
    WRITER --> STORE[(Object store / tape / offsite)]
```

The producer streams plaintext into the encryptor and streams ciphertext out
to the object store; peak memory is bounded by the chunk parameter `F` (default
128 codepoints per chunk, hard cap 16 384), not by backup size.

### 1.2 Chunk-by-chunk encryption path

Each chunk is encrypted as a self-contained v8 primitive call keyed by
`(sk_fmt, sub_nonce_i)`, where `sk_fmt = HMAC(sk, 0x0B || FORMAT_STREAM_AE_V8)`
and `sub_nonce_i = HMAC(sk_fmt, 0x0E || nonce || uint32_be(i))[:16]`
([SPEC.md §8.2](../SPEC.md)).

```mermaid
sequenceDiagram
    autonumber
    participant App as Backup job
    participant Enc as NAPQES v8<br/>encryptor
    participant KMS as KMS/HSM
    participant Store as Object store

    App->>KMS: Fetch key material sk
    KMS-->>Enc: sk (in-process, zeroized after use)
    Enc->>Enc: sk_fmt = HMAC(sk, 0x0B or FORMAT_STREAM_AE_V8)
    Enc->>Enc: Draw 16-byte CSPRNG nonce
    Enc->>Store: Write header (0x02 or F or nonce)
    loop For each F-codepoint chunk i in 0..C
        App->>Enc: feed chunk i (F codepoints, pad w/ HMAC filler if short)
        Enc->>Enc: sub_nonce_i = HMAC(sk_fmt, 0x0E or nonce or i)[:16]
        Enc->>Enc: masked_chunk = tokens XOR keystream(sk_fmt, sub_nonce_i)
        Enc->>Enc: chunk_tag_i = HMAC(sk_fmt, 0x0C or nonce or i or aad or masked_chunk)
        Enc->>Store: Write (len or masked_chunk or chunk_tag_i)
    end
    Enc->>Enc: sentinel_tag = HMAC(sk_fmt, 0x0D or nonce or C or aad or total_real_codepoints)
    Enc->>Store: Write sentinel (0x00 or C or total or sentinel_tag)
    Enc->>Enc: zeroize_key(sk, sk_fmt, sub_nonce_i)
```

**Key sizing choices for backup workloads:**

- **`F` (codepoints per chunk).** Larger `F` amortises per-chunk tag overhead
  (32 B) across more payload. For DB backups, `F = 4096` yields ≈ 655 kB per
  chunk frame with tag overhead ≈ 0.005 %. `F` is public and constant for the
  stream (bound into the header), so per-chunk ciphertext length is a pure
  function of `F` — no length leakage of chunk contents.
- **Parallel producers.** Independent tables/tablespaces can be encrypted as
  independent streams with independent nonces; this parallelises across
  cores without violating the no-nonce-reuse rule.
- **Compression order.** Compress *before* encrypting. Ciphertext is
  effectively random and does not compress; ratio gains must be captured
  upstream (`pg_dump -Z`, `gzip`, `zstd`).

### 1.3 Decryption / restore path

Decryption is symmetric and streams frame by frame. Critically, no plaintext
from chunk `i` is released to the caller until `chunk_tag_i` verifies
([SPEC.md §8.2 "Verify-before-yield"](../SPEC.md)):

```mermaid
sequenceDiagram
    autonumber
    participant Store as Object store
    participant Dec as NAPQES v8<br/>decryptor
    participant KMS as KMS/HSM
    participant DB as Restore target

    Dec->>Store: Read header
    Dec->>Dec: Parse 0x02 or F or nonce; derive sk_fmt
    KMS->>Dec: sk
    loop For each chunk frame i
        Store-->>Dec: (len or masked_chunk or chunk_tag_i)
        Dec->>Dec: Recompute chunk_tag_i'
        alt tag matches
            Dec->>Dec: sub_nonce_i; unmask; decode tokens
            Dec->>DB: yield chunk i plaintext
        else tag mismatch
            Dec->>DB: ABORT restore, raise auth failure
        end
    end
    Store-->>Dec: sentinel (0x00 or C or total or sentinel_tag)
    Dec->>Dec: Verify sentinel_tag (binds C and total_real_codepoints)
    alt sentinel ok
        Dec->>DB: strip filler from last chunk; commit restore
    else sentinel mismatch (truncation or reorder)
        Dec->>DB: ABORT; last chunk's real codepoints NOT emitted
    end
```

The sentinel is the anti-truncation and anti-splice checkpoint: any missing
tail frame, any reordered frame, or any chunk-count mismatch fails
verification and the restore aborts before the final chunk's real codepoints
are delivered.

---

## 2. How AEAD prevents data corruption

NAPQES is authenticated encryption with associated data (AEAD): every
ciphertext carries an HMAC-SHA256 tag over the ciphertext, the nonce, and
any AAD the caller supplied. In v8 streaming mode this is layered — a tag
per chunk plus a sentinel tag binding the chunk count — so corruption is
detected at chunk granularity, not only at end-of-stream.

### 2.1 What "corruption" means here

AEAD detects any change to the ciphertext bytes, the nonce, the AAD, or the
chunk ordering. This covers:

- **Bit rot** on disk / tape / object storage.
- **Truncation** (missing trailing frames or a lost sentinel).
- **Splicing** (frames from one backup grafted into another).
- **Reordering** (frames delivered out of sequence).
- **Active tampering** by an attacker with write access to the backup store.

It does **not** cover: a database-level corruption that was already present
in the plaintext before encryption (NAPQES faithfully encrypts whatever it
receives), nor a lost key (which is an availability problem, addressed in §3).

### 2.2 Tag structure and what each tag binds

```mermaid
flowchart TB
    subgraph STREAM["v8 streaming ciphertext"]
        H["Header<br/>0x02 || F || nonce (21B)"]
        subgraph C0["Chunk 0"]
            L0[len]
            M0[masked_chunk_0]
            T0["chunk_tag_0<br/>HMAC(sk_fmt, 0x0C||nonce||0||aad||m0)"]
        end
        subgraph C1["Chunk 1"]
            L1[len]
            M1[masked_chunk_1]
            T1["chunk_tag_1<br/>HMAC(sk_fmt, 0x0C||nonce||1||aad||m1)"]
        end
        subgraph CN["… Chunk C-1"]
            LN[len]
            MN[masked_chunk_N]
            TN[chunk_tag_N]
        end
        subgraph S["Sentinel"]
            S0["0x00 || C || total_real_codepoints"]
            ST["sentinel_tag<br/>HMAC(sk_fmt, 0x0D||nonce||C||aad||total)"]
        end
    end

    H --> C0 --> C1 --> CN --> S

    classDef tag fill:#ffe0e0,stroke:#a33
    class T0,T1,TN,ST tag
```

Each tag is a keyed HMAC over inputs the attacker cannot forge without the
key material:

| Tag | Domain | Binds |
|---|---|---|
| `chunk_tag_i` | `0x0C` | `sk_fmt`, `nonce`, chunk index `i`, AAD, `masked_chunk_i` |
| `sentinel_tag` | `0x0D` | `sk_fmt`, `nonce`, chunk count `C`, AAD, `total_real_codepoints` |

Because the chunk index is bound into every chunk tag, swapping two
otherwise-valid chunks produces two tag mismatches. Because `C` and the
real-codepoint count are bound into the sentinel, truncating the stream at a
chunk boundary is detected even if the remaining chunk tags are all valid.

### 2.3 Corruption detection decision flow (restore-time)

```mermaid
flowchart TD
    START([Restore begins]) --> READH[Read header]
    READH --> HOK{Header parses?<br/>version=0x02, F sane}
    HOK -- no --> FAIL1[Abort: malformed header]
    HOK -- yes --> LOOP[Read next frame]
    LOOP --> ISCHUNK{Chunk frame<br/>or sentinel?}
    ISCHUNK -- chunk --> READCH[Read len, masked_chunk, chunk_tag]
    READCH --> VER{Recomputed<br/>chunk_tag matches?}
    VER -- no --> FAIL2[Abort: bit rot / tamper /<br/>reorder on chunk i]
    VER -- yes --> YIELD[Decrypt, yield chunk plaintext]
    YIELD --> LOOP
    ISCHUNK -- sentinel --> READS[Read C, total, sentinel_tag]
    READS --> SVER{Recomputed<br/>sentinel_tag matches?}
    SVER -- no --> FAIL3[Abort: truncation /<br/>chunk-count mismatch]
    SVER -- yes --> COUNT{Observed chunks == C<br/>AND total consistent?}
    COUNT -- no --> FAIL4[Abort: frame injection /<br/>splice detected]
    COUNT -- yes --> STRIP[Strip filler from last chunk]
    STRIP --> DONE([Restore committed])

    classDef bad fill:#ffcccc,stroke:#a00
    class FAIL1,FAIL2,FAIL3,FAIL4 bad
```

Every failure path aborts the restore *before* any of the corrupt chunk's
plaintext reaches the target database. This is the RUP (release of
unverified plaintext) fix from CAV-001 ([SPEC.md §8.2, "Verify-before-yield"](../SPEC.md)),
and it is why the deprecated basic streaming format (§8) is forbidden for
new ciphertext ([SPEC.md §8, CVF7 fix](../SPEC.md)).

### 2.4 AAD as a binding contract

The AAD field is the operator's lever for **domain-binding** a backup to its
intended context. Anything put into AAD is authenticated but not encrypted,
so the caller can bind:

- Backup ID / timestamp (prevents replaying an old backup as a new one).
- Source database identity (prevents cross-restore into the wrong instance).
- Retention class / environment label (prevents prod backup landing in dev).

At restore time, the *same* AAD must be supplied; a mismatch fails every
tag. This turns AAD into a lightweight contract that the restore path
enforces cryptographically.

---

## 3. Backup and disaster recovery with NAPQES-encrypted DB backups

NAPQES protects the confidentiality and integrity of the backup blob. It does
not, on its own, provide the *availability* half of DR — that comes from
where and how the ciphertext and key material are stored. The pattern below
separates the two concerns.

### 3.1 Reference topology

```mermaid
flowchart LR
    subgraph PROD["Production site"]
        DB[(Primary DB)]
        BJ[Backup job]
        NENC[NAPQES v8 encryptor]
        DB --> BJ --> NENC
    end

    subgraph KMS_LAYER["Key management (independent failure domain)"]
        HSM[[Primary HSM / KMS]]
        HSMREP[[Replica HSM<br/>alt region]]
        SHAMIR[[Split key custody<br/>Shamir 3-of-5 offline]]
        HSM <-.replicate.-> HSMREP
        HSM -.escrow.-> SHAMIR
    end

    NENC <--"sk (fetched per stream,<br/>zeroized after use)"--> HSM

    subgraph STORAGE["Ciphertext replication (tiered)"]
        S1[(Hot: object store<br/>same region)]
        S2[(Warm: object store<br/>alt region, WORM)]
        S3[(Cold: offline tape<br/>air-gapped vault)]
        S1 --replicate--> S2
        S2 --archive--> S3
    end

    NENC --> S1

    subgraph DR["DR / restore site"]
        RJOB[Restore job]
        NDEC[NAPQES v8 decryptor]
        DB2[(Restored DB)]
        S1 -.pull.-> RJOB
        S2 -.pull if S1 lost.-> RJOB
        S3 -.pull if S1+S2 lost.-> RJOB
        HSMREP -.sk.-> NDEC
        SHAMIR -.reconstruct if HSMs lost.-> NDEC
        RJOB --> NDEC --> DB2
    end
```

Three independent failure domains — **ciphertext**, **key material**, and
**operational metadata** — each need their own DR story. Losing any one
must still leave a survivable path; losing two is a designed-for degraded
mode; losing all three is unrecoverable by construction (that is the
security property, not a bug).

### 3.2 Backup lifecycle timeline

```mermaid
sequenceDiagram
    autonumber
    participant Sched as Scheduler
    participant DB as Primary DB
    participant Enc as NAPQES encryptor
    participant KMS as KMS/HSM
    participant Hot as Hot object store
    participant Warm as Warm store (alt region)
    participant Cold as Cold tape vault
    participant Cat as Backup catalog

    Sched->>DB: Trigger consistent dump
    DB-->>Enc: Plaintext stream
    Enc->>KMS: Request sk (with backup-id in AAD)
    KMS-->>Enc: sk (short-lived handle)
    Enc->>Hot: Write v8 stream (header, chunks, sentinel)
    Enc->>Cat: Record (backup_id, nonce, aad, sha256(ciphertext), key_ref)
    Enc->>Enc: zeroize_key(sk)
    Hot->>Warm: Cross-region async replication
    Warm->>Cold: Nightly archive to WORM tape
    Note over Sched,Cat: Periodic restore drill (see 3.3)
    Sched->>Cat: Pick random backup_id
    Cat-->>Sched: Locate ciphertext + key_ref + aad
    Sched->>Enc: Decrypt to isolated DR sandbox
    Enc-->>Sched: Restore succeeds → drill passes<br/>else → page on-call
```

**Catalog contents.** The backup catalog is the third failure domain. It
holds *metadata about* backups — never key material, never plaintext — and
must itself be replicated. At minimum per backup: `backup_id`, source DB
identity, ciphertext location(s), the nonce (public), the AAD used, a
plaintext-independent integrity hash of the ciphertext object, and an
opaque `key_ref` the KMS can resolve.

### 3.3 Restore / disaster recovery decision path

```mermaid
flowchart TD
    INC[Disaster / restore requested] --> WHATLOST{What is lost?}

    WHATLOST -->|Primary DB only| PATH1[Standard restore]
    WHATLOST -->|Primary site| PATH2[DR-site restore]
    WHATLOST -->|Primary HSM| PATH3[Key recovery]
    WHATLOST -->|Ciphertext copies| PATH4[Storage recovery]

    PATH1 --> C1{Hot store<br/>reachable?}
    C1 -- yes --> R1[Pull from hot;<br/>decrypt with prod KMS]
    C1 -- no --> C2{Warm store<br/>reachable?}
    C2 -- yes --> R2[Pull cross-region;<br/>higher RTO]
    C2 -- no --> R3[Recall tape;<br/>RTO measured in hours]

    PATH2 --> DR1[Failover to DR site]
    DR1 --> DR2[Use replica HSM for sk]
    DR2 --> DR3[Pull from warm/cold]
    DR3 --> DR4[Decrypt, restore]

    PATH3 --> K1{Replica HSM<br/>alive?}
    K1 -- yes --> K2[Promote replica;<br/>continue]
    K1 -- no --> K3[Convene Shamir custodians<br/>3-of-5 offline shares]
    K3 --> K4[Reconstruct sk in HSM,<br/>rotate immediately after]

    PATH4 --> S1{Any tier<br/>survives?}
    S1 -- yes --> S2[Restore from surviving tier;<br/>re-replicate to lost tiers]
    S1 -- no --> S3[Unrecoverable by design;<br/>invoke business continuity plan]

    R1 --> VERIFY
    R2 --> VERIFY
    R3 --> VERIFY
    DR4 --> VERIFY
    K4 --> VERIFY
    S2 --> VERIFY

    VERIFY[Verify AEAD tags<br/>chunk-by-chunk + sentinel] --> VOK{All tags<br/>pass?}
    VOK -- yes --> APPLY[Apply to target DB;<br/>update catalog]
    VOK -- no --> QUAR[Quarantine object;<br/>try next replica;<br/>escalate to security]

    classDef bad fill:#ffcccc,stroke:#a00
    class S3,QUAR bad
```

### 3.4 Operational rules that make this actually work

- **Never store `sk` next to the ciphertext.** The whole design collapses
  if a single stolen tape or bucket contains both. Key material lives only
  in the KMS/HSM and its offline escrow.
- **Nonce uniqueness is non-negotiable.** v8 streaming is not
  misuse-resistant ([CAV-005 in SPEC.md §8.2](../SPEC.md)); nonce reuse
  across two streams under the same `sk` is catastrophic. Use the
  CSPRNG-drawn 16-byte nonce per stream — do not derive it from the
  backup ID or timestamp.
- **Key rotation ≠ ciphertext re-encryption.** Rotating `sk` in the KMS
  does not invalidate historical ciphertexts encrypted under the previous
  `sk`; retain retired keys in the KMS for the ciphertext retention
  window, or re-encrypt on rotation.
- **Restore drills verify AEAD.** A restore that never runs is a backup
  that does not exist. Schedule periodic drills that decrypt to an
  isolated sandbox; any tag failure surfaces silent corruption before an
  incident does.
- **Bind context into AAD.** Backup ID, source DB identity, environment,
  and retention class all belong in AAD so the restore path cannot
  accidentally cross-wire a backup into the wrong target. See §2.4.
- **Zeroize on the hot path.** `zeroize_key()` runs after every stream on
  both encrypt and decrypt sides ([project_fips140.md](../../MEMORY.md)
  Phase 3 work in the Rust core); do not let `sk` linger in a long-running
  process's heap.

---

## References

- [SPEC.md §5](../SPEC.md) — Block ciphertext wire format (v7).
- [SPEC.md §8.1](../SPEC.md) — v6s-ae streaming AE (per-chunk tags, sentinel).
- [SPEC.md §8.2](../SPEC.md) — v8 streaming AE (fixed-width tokens, per-chunk padding).
- [docs/CAVEATS.md](CAVEATS.md) — CAV-001 (RUP), CAV-005 (v8 nonce reuse).
- [docs/fips/KEY_MANAGEMENT.md](fips/KEY_MANAGEMENT.md) — Key lifecycle for FIPS 140-3 module boundary.
