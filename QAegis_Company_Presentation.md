# QAegis
## Post-Quantum Security for the Decade Ahead

*Three suites. One philosophy. Zero compromise.*

---

## The Threat Landscape Has Changed — Permanently

Three structural shifts are converging right now, and they cannot be addressed by patching existing tools.

**The Harvest-Now-Decrypt-Later threat is active today.** State-level adversaries are intercepting and archiving encrypted traffic in anticipation of a cryptographically relevant quantum computer. Every VPN session, every AI query, every command sent over a classical connection is a future liability. Federal Reserve research (FEDS 2025-093) models this as an active financial threat.

**CNSA 2.0 has a hard deadline.** The NSA's Commercial National Security Algorithm Suite 2.0 requires post-quantum networking to be preferred by 2026 and exclusive by 2030. This is not advisory — it is a procurement requirement for US government contractors and their entire supply chains.

**NIST standards are final.** FIPS 203, 204, and 205 were finalized in August 2024. The migration is no longer theoretical: Cloudflare reports that 43% of human HTTPS connections already use hybrid post-quantum key exchange.

> The window to act is not the future. It is now.

---

## QAegis: One Company, Three Interlocking Suites

QAegis was built around a single conviction: that post-quantum security must be sovereign, auditable, and deployable at every layer of the enterprise — from the encryption primitive to the AI inference pipeline to the network itself.

The three suites share one cryptographic foundation and one architectural principle: **no hidden coordinator, no opaque dependency, no trust you cannot verify yourself.**

| Suite | Layer | Core Claim |
|---|---|---|
| **NAPQES** | Cryptographic primitive | The only post-quantum AEAD with human-auditable keys and a proved, tunable bound on ciphertext-length leakage |
| **QAegis AI** | AI orchestration | The only enterprise AI platform with post-quantum signed, DLT-anchored, offline-verifiable inference provenance |
| **MeshWeave** | Network infrastructure | The only VPN that is simultaneously serverless, post-quantum at the identity layer, and CA-free |

No competitor ships all three. No competitor can — because closing each gap requires dismantling the architectural choices that define the incumbent's business model.

---

## Suite 1 — NAPQES
### The Cryptographic Core

*Noise-Augmented Post-Quantum Encryption System · v6 · Python · Rust · C*

---

### What It Is

NAPQES is an authenticated encryption scheme (AEAD) built exclusively from **HMAC-SHA256** — no block cipher, no elliptic curve, no lattice. It provides confidentiality, integrity, and authenticity in a single pass, and adds something no standard cipher offers: a **structured noise token layer** that makes every ciphertext appear the same length on the wire.

Every other AEAD in deployment — AES-GCM, ChaCha20-Poly1305 — hides content but not message shape. SIGINT services exploit ciphertext length to infer M&A commands, energy bids, and military C2 signals without breaking a single bit of encryption. NAPQES closes that attack surface by design.

**Key properties:**

- ~128.5-bit post-quantum security (post-Grover) at K=13 prime key elements
- 40/40 PASS on NIST SP 800-22 randomness tests across 10 million bits
- Rust core TVLA max t-statistic: 1.134 — well below the 4.5 threshold for constant-time verification
- Implementations in Python (reference), Rust (constant-time), and C — all cross-verified with Known Answer Test vectors

---

### The Three Differentiators No Competitor Offers

**1. No algebraic structure — no algebraic attack surface.**
AES-GCM operates over GF(2⁸) and GF(2¹²⁸). GHASH, the authentication function, is a polynomial over a finite field — the same mathematical structure that Shor-family quantum algorithms and algebraic cryptanalysis target. When a vulnerability hits AES-GCM, a full dependency audit takes eleven days and €140M for a defense prime. A complete NAPQES dependency audit takes four minutes: there is exactly one primitive to check.

**2. Human-auditable key management.**
NAPQES keys are ordered lists of prime integers in the range [1,000,000 – 15,000,000]. Any compliance officer can verify five properties — primality, distinctness, range, non-overlap with prior keys, and ordering — in under ten minutes, without a cryptographer, without an HSM vendor, without specialized tooling. This closes recurring qualified findings under DORA Art. 9, IAEA nuclear regulations, and IEC 62443 that AES opaque byte keys structurally cannot address.

**3. Traffic-pattern concealment as a tunable parameter.**
NAPQES pads every message into a power-of-two size bucket before encryption, and the ciphertext length is a function of that bucket and nothing else — not of the content, not of the key. This is a proved property (LH-IND-CPA-det, `docs/napseq-eprint-v3.tex`), and it bounds what an observer learns at 3.70 bits per message, against `H(n)` bits — everything — for AES-GCM and ChaCha20-Poly1305.

For a naval C2 channel the honest statement is this: under the **default** profile, a FIRE command (12–20 bytes) and a full mission parameter set (300–500 bytes) land in *different* buckets and remain distinguishable. Under the **fixed-frame profile** — a one-line sender-side setting, no wire-format change, no change at the receiver — they produce byte-identical ciphertext lengths and the fingerprint database becomes useless, provably and measurably. The customer chooses where to sit on that curve; no standardized AEAD offers the choice at all.

---

### Competitive Position

| Property | AES-256-GCM | ChaCha20-Poly1305 | **NAPQES** |
|---|---|---|---|
| No algebraic structure | ✗ | Partial | **✓** |
| Hardware-independent performance | ✗ | ✓ | **✓** |
| Bounded length leakage (padding profiles) | ✗ | ✗ | **✓** (≤3.70 bits; 0 with fixed-frame) |
| Human-auditable key format | ✗ | ✗ | **✓** |
| Single-primitive dependency audit | ✗ | ✗ | **✓** |
| FIPS 140-3 validated | ✓ | ✗ | Phase 4 (planned) |

NAPQES is not positioned as a replacement for AES-GCM in every deployment. It is the necessary choice when the threat model includes ciphertext-length leakage, hardware-constrained environments (RISC-V, ARM Cortex-M0, legacy PLCs), or compliance regimes that require a human-readable audit trail for key management.

---

### Where NAPQES Is Already Deployed

**OT / Critical Infrastructure (Legacy Shield Gateway).** A ruggedized bump-in-the-wire appliance wraps Modbus, DNP3, and OPC-UA traffic in NAPQES AEAD with zero firmware changes to plant equipment. Critically: HMAC-only authentication means nonce reuse — common in long-lived OT devices — does not expose key material. AES-GCM's GHASH leaks the authentication key on nonce reuse. Ships with IEC 62443-3-3 and NIS2 Art. 21 compliance dossiers.

**Naval & Defence C2.** Every command — from a single-word FIRE to a full mission parameter set — is padded with HMAC-derived noise tokens into identical-looking ciphertext blocks. Adversary traffic-analysis fingerprinting becomes useless. No AES-NI dependency: runs on drone MCUs and RISC-V.

**Insurance & Financial (DORA / Solvency II).** AES-GCM ciphertext length reveals message size. Treaty commands are 6–7 bytes; term sheets are 100–8,000 bytes. SIGINT services fingerprint traffic patterns to front-run reinsurance capacity. NAPQES noise tokens eliminate this attack. AAD-binding to device serial and policy number prevents OBD-II telematics replay attacks.

**Drone & IoT Firmware Protection.** NAPQES v6 encrypts firmware sections at rest in flash. The encrypted image produces only pseudorandom noise (entropy ≈ 8 bits/byte). AAD binding to device serial plus firmware version means a transplant attack fails authentication. Any single bit flip causes bootloader halt — no partial code execution.

---

## Suite 2 — QAegis AI
### Private AI Orchestration Platform

*Custom-built multi-agent system · No LangChain · No LlamaIndex · Runs entirely inside your perimeter*

---

### The Problem QAegis AI Solves

Enterprises block ChatGPT, Copilot, and Gemini because data leakage is a board-level risk. CISOs simultaneously face pressure to deploy AI-powered security tooling. Cloud AI cannot bridge this gap: the moment a prompt leaves the perimeter, the data sovereignty guarantee ends.

QAegis AI brings inference inside the perimeter, encrypts the entire pipeline with NAPQES, and wraps every AI output in a cryptographically signed, DLT-anchored credential that any third-party auditor can verify offline — without trusting QAegis servers.

---

### Four Reasoning Modes

**Standard.** Intent-based routing to specialist agents: web search, data analyst, file summarizer, news researcher, cross-analyzer, enterprise knowledge, enterprise analytics, and user-defined custom agents.

**Deep Thought.** Tree-of-Thoughts, 5-phase multi-step reasoning for complex analytical tasks.

**Cooperative Agents.** Multiple specialist agents collaborate simultaneously and synthesize a joint response.

**Atlas (Autonomous Planner).** The most powerful mode. Atlas decomposes a natural-language goal into a 2–8 step structured plan with a dependency graph, executes each step using nine tools (python_exec, bash_exec, web_search, fetch_page, http_request, write_file, enterprise_query, mcp_tool, llm_reason), self-heals on failure, and streams real-time progress via Server-Sent Events. Code executes inside an isolated Docker sandbox — non-root, no network, CPU/memory/PID limited. No user-supplied code is ever executed: Atlas generates code from natural-language hints.

---

### The Inference Passport — Verifiable AI Provenance

Every answer produced by QAegis AI ships with a **Sovereign Inference Passport (SIP)**: a portable, cryptographically verifiable credential that travels with the AI response as a sidecar JSON object and can be verified offline without access to QAegis servers.

The passport answers five questions:

| Question | What is recorded |
|---|---|
| **Who?** | Model identity + weights digest, post-quantum signed (ML-DSA-65 / Dilithium3) |
| **From what?** | Zero-knowledge commitment over input context and retrieved sources |
| **Where?** | Jurisdiction + hardware/enclave attestation |
| **Under what rules?** | Policy-as-code hash + guardrail configuration hash |
| **Trustworthy?** | Adversarial red-team verdict + deterministic replay digest, DLT-anchored |

The passport is signed with ML-DSA-65 (NIST FIPS 204) and anchored in a 5-node Byzantine Fault-Tolerant blockchain. SHA-256 Merkle proofs are offline-verifiable by any third-party auditor. Any byte change breaks the Merkle proof — the tamper-evidence is structural, not procedural.

This directly satisfies EU AI Act traceability requirements without relying on the provider's word.

---

### The Security Stack

**NAPQES-encrypted inference pipeline.** All inter-component AI traffic is encrypted with NAPQES. Prompt injection and model extraction attacks face a traffic-blind encrypted channel — the attacker cannot fingerprint which model is being queried or what the prompt structure is.

**Five-layer bot and agent protection.** User-agent blocklist (~50 automation identifiers including GPTBot, ClaudeBot, Playwright, HeadlessChrome, python-requests). Sliding-window rate limiter per IP. Signed HMAC behavior tokens issued on browser fingerprint collection and required on every sensitive request. Honeypot fields. JWT gate (HS256, 7-day expiry).

**Immutable DLT audit chain.** Every security event — authentication, bot blocks, MFA events, admin operations, BPM audit entries, IAM events — is SHA-256 hashed, Merkle-tree batched, and sealed into a 5-node BFT blockchain. The chain is hash-linked and append-only: any modification invalidates all subsequent blocks. Offline verification requires no access to QAegis infrastructure.

**NAPQES Key Vault.** Chat sessions are encrypted at rest using the NAPQES "EPI Cypher." Key storage and rotation is handled by a dedicated Key Vault service. Keys never leave the vault unencrypted.

---

### Competitive Position

The Inference Passport is not a single feature — it is the emergent product of five capabilities that must all exist and be integrated. A competitor attempting to replicate it must independently ship:

1. Sovereign local inference (LLM runs on hardware the customer controls)
2. An immutable DLT audit chain
3. Post-quantum cryptography across the signing layer
4. Deterministic agent replay (so proofs are checkable, not merely claimed)
5. An independent adversarial red-team engine embedded in every response

No existing product — ChatGPT, Copilot, Gemini, or any open-source LLM orchestrator — ships any of these five. QAegis AI ships all five integrated into a single offline-verifiable credential. The moat is integration depth, which is far harder to copy than any single algorithm.

---

### Multi-Provider Inference — Fully Air-Gappable

Ollama · LM Studio · llama.cpp · Azure OpenAI · AWS SageMaker · VertexAI · vLLM. Any model, one platform. Enterprises can run entirely on local hardware with no external API calls — or route to cloud providers when sovereign deployment is not required. The security and audit stack is identical in both configurations.

---

## Suite 3 — MeshWeave
### Serverless Post-Quantum Mesh Network

*No server to breach. No CA to compromise. Quantum-safe today — and for the decade ahead.*

---

### The Fatal Flaw in Every VPN Shipping Today

Every incumbent mesh VPN — Tailscale, NetBird, ZeroTier, NymVPN — keeps a coordination server at the center of its architecture. That server controls identity, stores session metadata, and maintains the full peer topology. It is simultaneously a single legal target (one subpoena yields the whole network map) and a single technical target (breach the coordinator, breach the mesh).

Incumbents cannot remove this server. It is not an implementation detail — it is their subscription model. Tailscale's coordination server is architecturally inseparable from its business model. Making it serverless would require replacing their entire control plane. They cannot follow MeshWeave without dismantling what they sell.

MeshWeave makes **three simultaneous deletions** — each removes a whole category of risk:

| What is deleted | Because | Replaced by |
|---|---|---|
| The coordination server | Always-on, subpoena-able choke point | Self-certifying keys + decentralized DHT + direct P2P connections |
| The Certificate Authority | Adds a trust root that is not needed | Self-certifying peer IDs with a KERI-style key-event log for rotation |
| PQ signatures from the handshake | 3–4 KB blobs bloat every handshake and cause NAT fragmentation | KEM-implicit authentication — every handshake fits one network frame |

---

### Four-Layer Architecture

**L0 — Identity & Naming.** Peer identity is the hash of the public key (libp2p PeerID model). Anyone can verify the name-to-key binding by recomputing the hash — no CA, no controller, no directory. Long-term identity keys carry hybrid signatures: Ed25519 (classical) + ML-DSA-65 (NIST FIPS 204). If either algorithm holds, identity is secure. Key rotation is governed by a cryptographically chained KERI-style key-event log — auditable, quantum-safe, and requiring no live server.

**L1 — Decentralized Control Plane.** S/Kademlia DHT with disjoint lookups and eclipse resistance. Gossipsub peer exchange keeps routing tables warm between DHT refresh intervals — no heartbeat server required. CRDT-based access control lists over gossipsub achieve coordination-free eventual consistency: no server for join or leave operations. mDNS for zero-config local discovery.

**L2 — NAT Traversal.** AutoNAT v2 classifies each node's reachability. DCUtR hole-punching achieves approximately 70% direct connection success, validated across 4.4 million live attempts in the IPFS network. For the remaining ~30% (symmetric NAT pairs, CGNAT): Circuit Relay v2. Any public peer can act as a relay — they are dumb, blind, volunteer, and interchangeable. Relays forward sealed ciphertext they cannot read and are capacity-capped to prevent amplification abuse.

**L3 — Post-Quantum Data Plane.** Kernel WireGuard with ChaCha20-Poly1305 AEAD for the per-packet hot path — symmetric AEAD, quantum-safe by Grover, 128-bit post-quantum security on 256-bit keys. Rosenpass sidecar runs off the hot path: Classic McEliece + ML-KEM (NIST FIPS 203) inject a hybrid post-quantum shared secret into the WireGuard PSK slot every ~2 minutes. Zero throughput penalty — symmetric AEAD runs at full kernel speed. At userspace GSO/GRO offload: 10–13 Gbps. With NIC/QAT offload: 40–100 Gbps.

---

### Competitive Position

No shipping product is simultaneously serverless, post-quantum at the identity layer, and CA-free. The gap is structural, not a matter of roadmap.

| Product | Truly Serverless? | PQ Key Exchange? | PQ Identity? | No CA? | Open Source? |
|---|---|---|---|---|---|
| Tailscale | ✗ | ✗ | ✗ | ✗ | Partial |
| NetBird | ✗ | Partial* | ✗ | ✗ | ✓ |
| ZeroTier | ✗ | ✗ | ✗ | ✗ | Partial |
| NymVPN | ✗ | Partial* | ✗ | ✗ | Partial |
| **MeshWeave** | **✓** | **✓** | **✓** | **✓** | **✓** |

\* Partial = data plane only. Identity and control plane remain classically secured. NetBird's Rosenpass integration protects the PSK but still uses a classically-signed CA for identity — the gap MeshWeave closes.

The identity gap is the critical distinction. iroh's own documentation acknowledges: "endpoint identity is still Ed25519." NetBird's Rosenpass protects the session key but not the long-term identity. MeshWeave is the only product where a "harvest-now-decrypt-later" adversary recording today's traffic cannot use a quantum computer to recover peer identities — because those identities are hybrid PQ from the start.

---

### Who Buys MeshWeave

**Enterprise zero-trust teams.** Fortune 500 IT modernizing their perimeter. No SaaS control plane to trust, breach, or pay per seat. CNSA 2.0 compliant.

**Government and defense.** Sovereign and air-gapped deployments with strict data-localization requirements. No cloud coordinator means no foreign jurisdiction exposure. Fully offline-capable.

**Media, legal, and NGOs.** Journalists, lawyers, and activists in adversarial environments. Censorship-resistant by design: there is no server to block, seize, or subpoena.

**Financial and healthcare.** Regulated sectors facing DORA, HIPAA, and CNSA 2.0 simultaneously. Harvest-now-decrypt-later is documented in Federal Reserve research as a board-level requirement.

---

## The Integrated Stack — Why Three Suites Become One Platform

The three suites address different layers of the same problem, and they are designed to work together:

**NAPQES** provides the cryptographic primitive that both QAegis AI and MeshWeave rely on. It is not a marketing integration — QAegis AI uses NAPQES as the "EPI Cypher" for chat sessions at rest and for post-quantum signing in the Inference Passport. VALE, the lawful escrow layer built into QAegis AI, protects escrow keys with FrodoKEM-640-AES and uses NAPQES for the transparency log.

**QAegis AI** provides the intelligence layer that operates securely inside the perimeter. The NAPQES-encrypted inference pipeline ensures that AI queries — which contain an organization's most sensitive operational data — never leave the network unprotected. The Inference Passport provides the audit trail that regulated industries require under the EU AI Act and sector-specific compliance frameworks.

**MeshWeave** provides the network infrastructure that makes sovereign deployment viable at scale. An enterprise running QAegis AI in Atlas mode across distributed sites needs a network that cannot be subpoenaed, cannot be compromised at the coordinator, and is already quantum-safe — so that the AI outputs protected by the Inference Passport are not undermined by a classically-encrypted network.

The three suites together offer something no single competitor can match: **a post-quantum security stack that runs entirely inside the customer's sovereign perimeter, with cryptographic audit evidence at every layer, and zero dependency on any external trust anchor.**

---

## Why the Market Cannot Easily Follow

The incumbents in each space have a structural problem, not a technical one.

In the VPN market, Tailscale, NetBird, and ZeroTier generate recurring revenue from their coordination servers. Removing those servers would end their subscription model. They cannot make MeshWeave's core architectural choice without destroying their business.

In the AI market, cloud providers (Microsoft, Google, OpenAI) cannot offer sovereign local inference while maintaining their cloud model. A product that runs entirely inside a customer's air-gapped network, with no telemetry, no prompt data, and no model usage data flowing to the provider, is structurally incompatible with their business.

In the encryption market, AES-GCM and ChaCha20-Poly1305 are standards — their key formats are fixed, their dependency chains are public, and their traffic patterns are well-characterized by SIGINT services. A standard cipher cannot add a noise token layer without changing the standard.

QAegis does not have to outrun incumbents on features. The architectural choices the incumbents made in order to build their current businesses are the same choices that prevent them from offering what QAegis offers.

---

## Maturity & Transparency

QAegis does not overstate readiness. Here is the honest state of each suite.

**NAPQES.** Wire format v6 is frozen with a stability guarantee. Rust constant-time core is complete with published TVLA attestation (max t = 1.134). Cross-language Known Answer Test vectors exist across Python, Rust, and C. The IND-CCA formal proof and third-party cryptanalytic audit are in progress. FIPS 140-3 CMVP submission is planned (Phase 4). An IETF Internet-Draft (draft-napqes-aead-00) is ready for submission.

**QAegis AI.** The full platform — Atlas, Cooperative Agents, Inference Passport, DLT audit chain, NAPQES pipeline, BPM engine — is deployed and operational. Multi-provider inference supports Ollama, LM Studio, llama.cpp, Azure OpenAI, AWS SageMaker, VertexAI, and vLLM. Enterprise connectors for SharePoint, Confluence, Salesforce, HubSpot, and SQL/NoSQL databases are production-ready.

**MeshWeave.** The complete cryptographic and control-plane stack is implemented and tested: hybrid PQ identity, self-certifying PeerIDs, KERI-style key-event log, OR-Set CRDT ACLs, LAN UDP multicast discovery, ChaCha20-Poly1305 tunnel, ML-KEM-768 PSK rotation, CLI-to-daemon IPC, and HTTP management API with web dashboard. Wide-area Kademlia DHT and full WireGuard kernel data path are on the Stage 1–2 roadmap.

---

## Three Steps Forward

**01 — Technical Deep-Dive.**
A 30-minute session with QAegis engineering. Review the NAPQES security target, KAT vectors, Inference Passport specification, and DLT audit attestations. No sales agenda — technical rigour only.

**02 — Vertical Mapping Workshop.**
Identify which of the five verticals (OT/critical infrastructure, insurance/financial, naval/defence, drone/IoT, VALE lawful escrow) align with your clients' immediate regulatory pain points. Produce a joint go-to-market outline mapping compliance requirements to deployment mode.

**03 — Pilot Statement of Work.**
8–12 week fixed-fee pilot on a single conduit or deployment. Outcome: compliance evidence package, deployment template, and a co-investment decision for broader rollout.

---

*contact@quantumaegis.ai · quantumaegis.ai*

---

*QAegis · July 2026 · Confidential*
