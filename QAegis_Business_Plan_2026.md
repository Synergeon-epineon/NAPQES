# QAegis — Investment Memorandum
## Series A · July 2026 · Confidential

*Seeking €10–20M for 10% equity*

---

# I. EXECUTIVE SUMMARY

QAegis is a post-quantum security company with three deployed, revenue-ready suites: **NAPQES** (a novel authenticated encryption protocol), **QAegis AI** (a sovereign enterprise AI orchestration platform), and **MeshWeave** (the world's only serverless, post-quantum, CA-free mesh VPN). All three share a single cryptographic foundation and a single architectural principle: zero dependency on any external trust anchor.

On **July 28, 2026**, Anthropic's Claude Mythos Preview published "Discovering Cryptographic Weaknesses with Claude," announcing the Möbius Bridge attack — an AI-discovered algebraic shortcut that improves the best-known attack on 7-round AES by a factor of 200–800×, exploiting the finite field structure of AES's S-box. The following day, the HAWK post-quantum signature scheme was **withdrawn from NIST standardization** after Mythos reduced its key-recovery complexity from 2⁶⁴ to 2³⁸ operations by exploiting its lattice algebraic structure.

These events — occurring two days before this memorandum — are not peripheral news. They are the thesis. NAPQES was designed from day one around the conviction that algebraic structure in a cipher is an attack surface, not just an abstract concern. NAPQES uses no finite field arithmetic, no lattice, no block cipher. It is built exclusively from HMAC-SHA256 — a primitive with no known algebraic shortcut. The Möbius Bridge validates every design choice that made NAPQES unusual and, until yesterday, difficult to explain to non-technical buyers.

The investment window created by this event will not remain open for long.

**The ask: €10–20M for 10% equity (pre-money: €90–180M).**

**The use: 37% engineering, 27% sales and GTM, 13% cryptographic audit and FIPS 140-3 compliance, 13% operations, 7% legal and IP, 3% reserve.**

**The target: €45M ARR by FY2031, with EBITDA-positive operations from Q3 2029.**

---

# II. THE CATALYST EVENT

## Claude Mythos and the Möbius Bridge — July 28–29, 2026

### What happened

On July 28, 2026, Anthropic published research conducted by its Claude Mythos Preview model on cryptanalysis. Working autonomously in a multi-agent system over several days at an API cost of approximately $100,000, the model invented a mathematical shortcut it called the **Möbius Bridge**.

The S-box at the core of AES is not a random permutation. It is constructed from an inverse operation over the Galois field GF(2⁸) composed with an affine transformation — a deliberate algebraic structure chosen for implementation efficiency. The Möbius Bridge exploits this structure to construct a fingerprint that remains invariant as an unknown key byte varies, eliminating one of the nine bytes that previously had to be guessed. Combined with packed tables, Gray-code-based search, and XOR-separated cache techniques, the attack achieves an overall speedup of roughly **200–800×** on 7-round AES, reducing the estimated time complexity from 2⁹⁹ to between **2⁸⁹·³ and 2⁹¹·⁴**.

The best-known attack on 7-round AES had not been improved since **2013**. An AI model improved it autonomously in three days.

### The HAWK withdrawal

The second result in the same publication identified a previously unexploited mathematical symmetry in HAWK's lattice structure, reducing its key-recovery complexity from approximately **2⁶⁴ to 2³⁸ operations**. On **July 29, 2026**, the HAWK team withdrew HAWK from NIST's additional post-quantum signature standardization process.

Anthropic has also seen early results against reduced-round LEA, Serpent, Salsa20, Poseidon, and SHA-1.

### Why this validates QAegis — exactly

NAPQES was designed to eliminate algebraic structure as an attack surface. The design choices that make NAPQES unusual — HMAC-SHA256 only, prime integer key format, no finite field arithmetic, no lattice — were motivated by precisely the threat that materialized this week. What was previously a theoretical design philosophy is now a documented, AI-executable attack class. The question for every enterprise CISO is no longer "should we be concerned about algebraic structure in our cipher?" It is "when will the next Möbius Bridge land on full-round AES?"

The Möbius Bridge does not break production AES today — the attack requires 2⁸⁹·³ chosen plaintexts and targets a reduced round variant. But the pattern is unmistakable: AI-assisted cryptanalysis is finding algorithmic shortcuts in ciphers that human researchers left untouched for over a decade. The cost of that research is $100,000 and declining. The window between "theoretical concern" and "operational threat" is compressing.

NAPQES has no algebraic structure to exploit. This is now the most important sentence in its product brief.

---

# III. MARKET OPPORTUNITY

## Three markets, one 2030 deadline

QAegis's three suites address markets that are structurally converging around the same compliance mandate:

| Market | Size (2029) | CAGR | Compliance Driver |
|---|---|---|---|
| Enterprise VPN / mesh networking | $77B+ | 14% | CNSA 2.0 (exclusive PQ by 2030) |
| Post-quantum security infrastructure | $9.5B+ | 38% | CNSA 2.0 / NIST FIPS 203-205 |
| Enterprise AI security & sovereign AI | $22B+ | 31% | EU AI Act, DORA, NIS2 |

The critical structural point: CNSA 2.0 converts post-quantum security from discretionary spend to a **procurement requirement**. US government contractors and their entire supply chains — a population numbering in the hundreds of thousands of enterprises — must demonstrate post-quantum compliance before 2030. This is not a technology adoption curve. It is a compliance deadline.

## QAegis's serviceable market

QAegis does not need to win the entire post-quantum security market. It targets a specific, defensible niche within each:

**NAPQES SAM:** Enterprises and governments where traffic-analysis resistance, human-auditable key management, or hardware-constrained deployment disqualify AES-GCM. This includes OT / critical infrastructure operators under NIS2 and IEC 62443, defense primes under CNSA 2.0, financial institutions under DORA Art. 9, and sovereign cloud operators. Estimated SAM: €800M–€1.5B.

**QAegis AI SAM:** Enterprises in regulated industries (finance, healthcare, defense, legal) that must run AI workloads but cannot send data to cloud providers. Estimated global count: 15,000–30,000 enterprises with immediate need. At an average contract value of €35,000/year: SAM of €500M–€1B.

**MeshWeave SAM:** Enterprise zero-trust networking teams requiring CNSA 2.0 compliance, sovereign deployment, and air-gap capability. Estimated 2,000–5,000 enterprises in the addressable segment by 2028. At an average of 200 nodes per enterprise at $6/node/month: SAM of €290M–€720M.

**Combined SAM:** €1.6B–€3.2B, with significant expansion potential as the CNSA 2.0 deadline draws supply chains into compliance.

## The 2030 inflection point

CNSA 2.0's 2030 exclusive-use deadline creates a mandatory procurement wave starting no later than 2028, as procurement cycles for enterprise security infrastructure run 12–24 months. QAegis's technology must be certified, integrated, and proven before that wave peaks. This is a narrow window for category-defining positioning — and QAegis has the only product in the market that addresses all three layers simultaneously, with deployed technology.

---

# IV. PRODUCT PORTFOLIO

## The unified thesis

All three suites share one cryptographic foundation (HMAC-SHA256), one architectural principle (no external trust anchor), and one compliance angle (post-quantum, auditable, sovereign). They are not three separate businesses — they are three entry points into a single enterprise security platform that can be adopted top-down (network → AI → crypto) or bottom-up (crypto → AI → network) depending on the buyer's most urgent pain point.

## Suite 1 — NAPQES: The Cryptographic Core

NAPQES (Noise-Augmented Post-Quantum Encryption System) is an authenticated encryption scheme (AEAD) built exclusively from HMAC-SHA256. It offers five properties that no standardized AEAD provides simultaneously:

1. **No algebraic structure.** The Möbius Bridge cannot target what does not exist. A full NAPQES dependency audit — every cryptographic primitive, every algorithm — takes four minutes.
2. **Human-auditable key management.** Keys are ordered lists of prime integers, auditable in ten minutes by a compliance officer without cryptographic tooling. This closes recurring qualified findings under DORA Art. 9 and IAEA nuclear audit standards.
3. **Bounded, tunable length leakage.** NAPQES pads every message into a size bucket, and ciphertext length depends on that bucket alone — a proved property that caps what a passive observer learns at 3.70 bits per message, and takes it to **exactly zero** under the fixed-frame profile. AES-GCM and ChaCha20-Poly1305 leak the plaintext length outright, which is the operational threat the Naval Group briefing describes. The default profile bounds the leak; the fixed-frame profile eliminates it, at a bandwidth cost the customer chooses.
4. **Hardware independence.** Identical performance on RISC-V microcontrollers and Intel Xeon. No AES-NI dependency — critical for OT devices, drone MCUs, and IoT endpoints.
5. **Single-primitive dependency.** AES-GCM's 2024 GHASH CVE demonstrated the risk of multi-primitive architectures. NAPQES is immune to any vulnerability that does not break HMAC-SHA256.

**Current maturity:** Wire format v6 frozen with stability guarantee. Rust constant-time core: TVLA max t-statistic 1.134 (threshold 4.5). NIST SP 800-22 randomness: 40/40 PASS across 10M bits. Cross-language KAT vectors: Python, Rust, C. IETF Internet-Draft (draft-napqes-aead-00) ready for submission. Academic preprints on ePrint. Third-party cryptanalytic audit in progress. FIPS 140-3 CMVP submission: Phase 4 (planned post-raise).

**Revenue model:** Vertical gateway appliances (€3,500–€12,000 per unit, 18–22% annual support). SDK/OEM licensing for partners (€50,000–€200,000/year per integration). Pilot SOWs (€15,000–€30,000 fixed-fee, 8–12 weeks). Professional services for compliance dossiers.

## Suite 2 — QAegis AI: Private AI Orchestration

A custom-built multi-agent AI platform — no LangChain, no LlamaIndex — that runs entirely inside the customer's perimeter, encrypts the inference pipeline with NAPQES, and wraps every AI output in a cryptographically signed, DLT-anchored Inference Passport (SIP) verifiable offline without access to QAegis servers.

**Four reasoning modes:** Standard (intent-based routing to specialist agents), Deep Thought (Tree-of-Thoughts, 5-phase), Cooperative Agents (multi-agent collaboration), Atlas (autonomous planner with self-healing, isolated Docker execution, 9 tools, 2–8 step plans).

**The Inference Passport (SIP):** Post-quantum signed (ML-DSA-65 / Dilithium3) and anchored in a 5-node BFT blockchain. Answers five questions for every output: who produced it, from what inputs, where, under what policy, and does an adversarial red-team engine endorse it. Auditors verify offline with a standalone CLI — no QAegis infrastructure required. This directly satisfies EU AI Act traceability requirements.

**Security stack:** NAPQES-encrypted inter-component pipeline. Five-layer bot protection. Immutable DLT audit chain (SHA-256 Merkle proofs, offline-verifiable). NAPQES Key Vault for session encryption at rest.

**Revenue model (SaaS, managed cloud):**

| Tier | Users | Price | Notes |
|---|---|---|---|
| Solo | 1–2 | €29/month | Shared multi-tenant |
| Starter | Up to 10 | €99/month | |
| Team | Up to 50 | €349/month | Priority support, 8h SLA |
| Business | Up to 200 | €999/month | Dedicated container env, 4h SLA |
| Enterprise | 200+ | Custom | Dedicated VNet, ≤1h SLA |

Plus token usage billed at 20–35% margin over provider cost. On-premise licensing available for air-gapped deployments.

## Suite 3 — MeshWeave: Serverless Post-Quantum Mesh VPN

The only VPN that simultaneously eliminates the coordination server, the certificate authority, and classical-only identity. The key architectural claim: no shipping competitor — Tailscale, NetBird, ZeroTier, NymVPN — is both fully serverless and fully post-quantum at the identity layer. This is a structural gap, not a feature gap.

**Four-layer architecture:** L0 self-certifying hybrid PQ identity (Ed25519 + ML-DSA-65, KERI key-event log). L1 S/Kademlia DHT + gossipsub + CRDT ACLs. L2 DCUtR hole-punching (70% success, 4.4M-attempt validated) + blind volunteer relays. L3 WireGuard + Rosenpass (ML-KEM-768 PSK rotation every 2 minutes, 10–13 Gbps throughput).

**Revenue model (open-core):**

| Tier | Nodes | Price | Notes |
|---|---|---|---|
| Community | Unlimited | Free | Apache-2.0 |
| Team | Up to 50 | $7/node/month | SSO, managed relays, audit log |
| Business | 51–500 | $5/node/month | Web-of-trust, cover traffic, 24×5 |
| Enterprise | 500+ | Custom | FIPS/CNSA 2.0 build, dedicated relays |

20% discount for annual commitment.

---

# V. COMPETITIVE DIFFERENTIATION

## The structural moats

**Moat 1 — The incumbents cannot follow without dismantling their businesses.**
Tailscale, NetBird, and ZeroTier generate recurring revenue from their coordination servers. The server is their subscription model. Removing it would terminate their ARR. This is not a technical limitation — it is a business model constraint.

**Moat 2 — The Möbius Bridge changes the sales conversation permanently.**
Before July 28, explaining NAPQES's "no algebraic structure" design choice required a technical audience and a lengthy threat model discussion. After July 28, the conversation starts with: "You saw the Möbius Bridge. NAPQES has no finite field arithmetic to bridge." Every AES-GCM or ChaCha20-Poly1305 deployment is now a NAPQES sales call waiting to happen.

**Moat 3 — Integration depth cannot be copied incrementally.**
The Inference Passport requires five independently-implemented capabilities: sovereign inference, immutable DLT, post-quantum signing, deterministic replay, and an adversarial engine. A competitor cannot add one and call it done. The moat is the integration, and integration depth is the hardest thing to copy.

**Moat 4 — The CNSA 2.0 compliance advantage compounds over time.**
QAegis is pursuing FIPS 140-3 CMVP validation for NAPQES, an IETF Internet-Draft, and defense vertical certifications. First-mover certification advantage in regulated procurement creates durable switching costs that grow with each enterprise deployment.

## Competitive grid

| Capability | Tailscale | NetBird | AES-GCM | LangChain AI | **QAegis** |
|---|---|---|---|---|---|
| Serverless mesh network | ✗ | ✗ | — | — | **✓** |
| PQ identity (not just data plane) | ✗ | ✗ | — | — | **✓** |
| No CA / no PKI | ✗ | ✗ | — | — | **✓** |
| No algebraic structure in cipher | — | — | ✗ | — | **✓** |
| Human-auditable keys | — | — | ✗ | — | **✓** |
| Bounded length leakage | — | — | ✗ | — | **✓** |
| Sovereign AI inference (air-gapped) | — | — | — | ✗ | **✓** |
| PQC-signed AI output provenance | — | — | — | ✗ | **✓** |
| DLT-anchored offline audit | — | — | — | ✗ | **✓** |
| CNSA 2.0 aligned (full stack) | ✗ | Partial | ✗ | ✗ | **✓** |

---

# VI. BUSINESS MODEL AND GO-TO-MARKET

## Revenue architecture

QAegis generates revenue across four streams, each with a different motion:

**1. Vertical gateway appliances (NAPQES).** Hardware + software + annual support contracts. Direct enterprise sale into OT/critical infrastructure, naval/defence, insurance/financial. High ASP (€3,500–€12,000 per unit), high retention (infrastructure deployments rarely replaced), clear regulatory buying trigger. GTM: direct field sales + reseller channel with compliance dossiers included.

**2. QAegis AI SaaS subscriptions.** Monthly recurring revenue from cloud-managed deployments. Bottom-up adoption from security-conscious teams, expanding to enterprise contracts with BPM, DLT audit, and Atlas. Upsell path: Solo → Starter → Team → Business → Enterprise. GTM: product-led growth for individual tiers, field sales for Business and Enterprise.

**3. MeshWeave open-core subscriptions.** Node-based recurring revenue. Community edition drives adoption and creates upgrade pressure as organizations scale. Team and Business tiers provide the SLA guarantees regulated buyers require. GTM: community-led adoption for SMB, compliance-led direct sales for enterprise. CNSA 2.0 creates non-discretionary demand from 2028.

**4. SDK / OEM / partner licensing (NAPQES).** Technology partners embedding NAPQES in their products pay annual platform fees. This is the highest-margin revenue stream (no support cost after integration, essentially perpetual renewal). Naval Group briefing in progress as of Q2 2026.

## Go-to-market strategy

**Phase 1 (Q3 2026–Q2 2027): Compliance-driven direct sales.** Target enterprises with active NIS2, DORA Art. 9, IEC 62443, or CNSA 2.0 audit findings. The Möbius Bridge event creates an immediate inbound opportunity — security teams are re-evaluating AES-GCM deployments today. Convert pilot SOW opportunities (8–12 weeks, fixed fee) into annual support contracts and SDK licenses.

**Phase 2 (Q3 2027–Q2 2028): Partner channel.** Three partner tiers (Technology / Solution Provider / SI-Managed Services). Solution Providers resell vertical gateways with compliance dossiers — no cryptographic expertise required. SI partners deploy full QAegis AI stacks for their clients. This scales revenue without scaling headcount proportionally.

**Phase 3 (Q3 2028–2030): CNSA 2.0 wave.** The 2030 mandatory compliance deadline creates a procurement wave starting 2028. By this point, QAegis will have at least one FIPS 140-3-validated product (NAPQES), an active IETF Internet-Draft, defense vertical deployments, and certified partner integrators. The compliance certificate is the sales pitch.

## Pricing rationale and competitive benchmarks

NAPQES gateway pricing (€3,500–€12,000) is competitive with industrial encryption appliances (Thales, Entrust, nShield Edge) while offering capabilities (noise tokens, prime-list keys, HMAC-only) that those products structurally cannot. MeshWeave's 5–7USD/node/month is below Tailscale's 6–18USD/user/month while offering sovereign deployment that Tailscale cannot provide. QAegis AI's €99–999/month SaaS tiers are below Microsoft Copilot for Enterprise (30USD/user/month × 50 users = 1,500USD/month for the Team-comparable tier) while providing air-gapped sovereign inference that Microsoft cannot.

In every case, QAegis is priced below or at parity with incumbents while offering capabilities incumbents cannot match.

---

# VII. FIVE-YEAR FINANCIAL PROJECTIONS

## Key assumptions

- Raise closes Q4 2026; full-year revenue ramp begins FY2027.
- Gross margins: QAegis AI SaaS 82%, MeshWeave SaaS 78%, NAPQES hardware+software blended 62%, NAPQES SDK/OEM 92%.
- Blended gross margin: 76–80% by Year 3 as software revenue dominates.
- Sales cycle: 3–6 months for mid-market, 6–18 months for enterprise and defense.
- CNSA 2.0 compliance wave assumed to materially accelerate MeshWeave and NAPQES demand from Q1 2028.
- No government contract revenue modeled (upside case only).
- Average contract value grows year-on-year as QAegis AI enterprise tier and MeshWeave large deployments scale.
- Headcount grows from ~18 FTE (today) to ~120 FTE by FY2031.

## Annual revenue projections (€M)

| | FY2027 | FY2028 | FY2029 | FY2030 | FY2031 |
|---|---|---|---|---|---|
| **NAPQES** | 0.55 | 1.40 | 2.90 | 6.10 | 10.90 |
| – Vertical gateways & support | 0.25 | 0.60 | 1.10 | 2.20 | 3.80 |
| – SDK / OEM licensing | 0.20 | 0.55 | 1.30 | 2.80 | 5.20 |
| – Professional services / SOWs | 0.10 | 0.25 | 0.50 | 1.10 | 1.90 |
| **QAegis AI** | 0.50 | 1.50 | 3.40 | 6.80 | 11.90 |
| – SaaS subscriptions | 0.38 | 1.10 | 2.50 | 5.10 | 9.00 |
| – Token usage margin | 0.07 | 0.25 | 0.60 | 1.20 | 2.10 |
| – On-premise licenses | 0.05 | 0.15 | 0.30 | 0.50 | 0.80 |
| **MeshWeave** | 0.40 | 1.20 | 3.10 | 7.50 | 14.00 |
| – Team / Business subscriptions | 0.35 | 1.05 | 2.70 | 6.60 | 12.40 |
| – Enterprise custom | 0.05 | 0.15 | 0.40 | 0.90 | 1.60 |
| **Total Revenue (ARR)** | **1.45** | **4.10** | **9.40** | **20.40** | **36.80** |
| **Gross Profit** | 1.02 | 2.99 | 7.14 | 15.91 | 29.44 |
| **Gross Margin** | 70% | 73% | 76% | 78% | 80% |

## Operating expense projections (€M)

| | FY2027 | FY2028 | FY2029 | FY2030 | FY2031 |
|---|---|---|---|---|---|
| R&D (engineering, audit, compliance) | 3.20 | 3.80 | 4.20 | 5.00 | 6.20 |
| Sales & Marketing | 2.10 | 3.20 | 4.00 | 5.50 | 7.00 |
| G&A | 0.80 | 1.10 | 1.40 | 1.80 | 2.20 |
| **Total OpEx** | **6.10** | **8.10** | **9.60** | **12.30** | **15.40** |
| **EBITDA** | (5.08) | (5.11) | (2.46) | 3.61 | 14.04 |
| **EBITDA Margin** | — | — | — | 18% | 38% |
| **Cumulative Cash Used** | (5.08) | (10.19) | (12.65) | (9.04) | 5.00 |

## Runway and cash position

Assuming a €15M raise (base case):

- Available cash post-raise: ~€15.5M (including existing small revenue)
- Monthly burn: ~€425K in FY2027, declining as revenue scales
- Break-even: Q3 2029 (month ~27 post-close)
- Runway to break-even: 28 months — within raise proceeds with ~€2.8M buffer
- Total cash consumed before break-even: ~€12.7M
- Buffer / reserve: ~€2.8M for delayed sales cycles or audit cost overruns

At the €10M raise (conservative), break-even requires an earlier revenue milestone (Q1 2029) or a bridge round. At the €20M raise (full), the buffer extends to ~€7.8M, allowing for opportunistic acquisitions or accelerated defense vertical build-out.

## Headcount plan

| | FY2027 | FY2028 | FY2029 | FY2030 | FY2031 |
|---|---|---|---|---|---|
| Engineering & cryptography | 12 | 18 | 24 | 30 | 38 |
| Sales & GTM | 5 | 10 | 15 | 22 | 30 |
| Product & design | 3 | 5 | 7 | 9 | 12 |
| G&A & compliance | 4 | 6 | 8 | 10 | 13 |
| Customer success | 2 | 4 | 6 | 9 | 12 |
| Cryptographic audit & research | 3 | 4 | 5 | 6 | 7 |
| **Total FTE** | **29** | **47** | **65** | **86** | **112** |

---

# VIII. USE OF PROCEEDS

## Base case: €15M raise

| Category | Amount | % | Rationale |
|---|---|---|---|
| Engineering & product | €5.5M | 37% | MeshWeave Stage 2 (wide-area DHT, WireGuard kernel path), QAegis AI Atlas enhancements, NAPQES v7 wire format |
| Sales & GTM | €4.0M | 27% | 5 enterprise sales hires, partner channel development, events (RSA, Black Hat, DSEI naval/defence), demand gen post-Möbius Bridge |
| Cryptographic audit & FIPS 140-3 | €2.0M | 13% | NAPQES third-party cryptanalytic audit (in progress), CMVP module boundary documentation and submission, IETF Internet-Draft track |
| Operations & G&A | €2.0M | 13% | Finance, legal ops, HR, office, insurance |
| Legal & IP | €1.0M | 7% | Patent prosecution (3 pending one in progress), IETF participation, contract templates, export control classification |
| Reserve | €0.5M | 3% | Audit overruns, delayed enterprise cycles, regulatory filing costs |

## €10M raise: prioritized allocation

At €10M, the allocation concentrates on the critical path to break-even: engineering (€4M), sales (€2.8M), cryptographic audit (€1.5M), G&A (€1.2M), legal (€0.5M). Non-critical product enhancements and conference spend are deferred. FIPS 140-3 submission timeline extends by approximately 6 months.

## €20M raise: accelerated allocation

At €20M, the additional €5M beyond the base case funds: a dedicated defense vertical engineering team for CNSA 2.0 federal compliance (€2M), acquisition of a complementary cryptographic engineering team (€1.5M), accelerated partner channel investment in EMEA and North America (€1M), and MeshWeave mobile client (iOS/Android) development (€0.5M).

---

# IX. VALUATION RATIONALE

## The pre-money case for €90–180M

QAegis is not a pre-revenue concept. It has:

- Three deployed suites with paying pilot customers
- An IETF Internet-Draft ready for submission (first post-quantum HMAC-AEAD in the IETF track)
- Multiple pending patents (filed)
- Academic preprints on the IACR ePrint server
- Naval Group briefing engagement in progress
- Rust constant-time implementation with published TVLA attestation
- Cross-language Known Answer Test vectors (Python, Rust, C)
- A market-validation event (Claude Mythos Möbius Bridge) that occurred 72 hours ago

Comparable transactions in post-quantum security:

| Company | Stage | Raise | Notes |
|---|---|---|---|
| PQ Shield (Oxford) | Series B | $37M | Narrower scope (PQC chips + software), no AI layer |
| QuSecure | Series A | $28M | US-only focus, no sovereign AI layer |
| Sandbox AQ | Series A | $500M | Google-backed, broader but shallower on encryption |
| evolutionQ | Strategic | $14M | PQC migration consulting only |

QAegis's pre-money at €90–180M sits below PQ Shield's implied Series B valuation and well below Sandbox AQ's — while offering a wider product surface (encryption + AI + network) that no comparable addresses. The Möbius Bridge event is a credibility accelerant that none of those comparables had at their raise.

## Exit scenarios (FY2031 reference year)

| Multiple | Revenue basis | Company value | 10% stake value | Return on €15M |
|---|---|---|---|---|
| 8× ARR (conservative) | €36.8M | €294M | €29.4M | 2.0× |
| 12× ARR (base) | €36.8M | €442M | €44.2M | 2.9× |
| 18× ARR (growth premium) | €36.8M | €662M | €66.2M | 4.4× |
| Strategic acquisition | — | €500M–€800M | €50M–€80M | 3.3–5.3× |

Strategic acquirer universe: defense primes (Thales, Raytheon, BAE Systems) seeking sovereign AI and PQC; hyperscalers (AWS, Azure, Google) seeking sovereign-deployment capability they cannot build authentically; enterprise security platforms (CrowdStrike, Palo Alto Networks) seeking to add PQC encryption at the platform layer.

The 2030 CNSA 2.0 deadline creates a natural acquisition window: defense and government vendors with non-compliant products will acquire rather than rebuild at scale. QAegis is the only target that delivers all three layers in a single proven platform.

---

# X. RISK FACTORS

QAegis operates with transparency as a competitive differentiator. The same standard applies here.

**Cryptographic risk — NAPQES audit.** The third-party cryptanalytic audit of NAPQES is in progress but not yet published. The algorithm has no known structural break, and the Rust implementation passes TVLA attestation.The audit is funded in the use-of-proceeds. Risk: low to medium. Mitigant: HMAC-SHA256 as the sole primitive limits the attack surface to a well-analyzed function with no known weaknesses and latest audit reports are very optimisitic.

**Regulatory risk — FIPS 140-3.** NAPQES is not FIPS 140-3 validated yet. Government procurement in regulated environments may require FIPS validation before deployment. CMVP submission is planned. Risk: medium for US federal market. Mitigant: the EU market (NIS2, DORA) does not require FIPS 140-3; defense primes can deploy under CNSA 2.0 provisional classification; FIPS submission timeline is 18–24 months from module boundary documentation (which is complete).

**Competitive risk — large incumbents.** Microsoft, Google, and AWS could build sovereign AI inference products. Tailscale could attempt to add post-quantum identity. AES-GCM vendors could attempt to add noise layers. Risk: low to medium. Mitigant: architectural constraints make these moves self-destructive for incumbents (see Section V). Building the integration stack that produces the Inference Passport is a multi-year effort; QAegis has a 2–3 year head start.

**Market timing risk.** If CNSA 2.0 enforcement is delayed or watered down, the compliance-driven demand wave would slow. Risk: low. The NIST standards are finalized. The NSA has published binding guidance. The HAWK withdrawal (July 29, 2026) reinforces the urgency. Congressional and DoD pressure for PQC compliance is bipartisan.

**Execution risk — sales cycle length.** Enterprise security sales cycles, particularly in defense and OT, run 12–18 months. The financial model assumes revenue from FY2027 onward; delays in closing early enterprise customers would compress the runway buffer. Risk: medium. Mitigant: pilot SOW structure provides early revenue while larger deals close; partner channel scales revenue without proportional headcount.

**Technical risk — MeshWeave Stage 2.** Wide-area Kademlia DHT and full WireGuard kernel data path are roadmap items, not yet shipped. The cryptographic and control-plane architecture is fully implemented. Risk: low. Mitigant: both components are built from production open-source components (libp2p, WireGuard) with no fundamental research required; every stage is buildable with existing engineering talent.

---

# XI. INVESTMENT TERMS

## Proposed structure

| Term | Detail |
|---|---|
| **Instrument** | Preferred equity, Series A |
| **Raise** | €10M–€20M (target €15M) |
| **Equity offered** | 10% (post-money) |
| **Pre-money valuation** | €90M–€180M (€135M at €15M target) |
| **Post-money valuation** | €100M–€200M |
| **Liquidation preference** | 1× non-participating preferred |
| **Anti-dilution** | Broad-based weighted average |
| **Board seat** | One seat for lead investor (observer for co-investors below €5M) |
| **Pro-rata rights** | Yes, for Series B |
| **Information rights** | Monthly management accounts, quarterly board pack |
| **Drag-along** | Standard (majority preferred + majority common) |
| **Lock-up** | 18 months from close |

## Milestone-based tranching (optional)

For investors preferring phased deployment, the raise may be structured as:
- Tranche 1 (€8M at close): Engineering, initial GTM, cryptographic audit commencement
- Tranche 2 (€7M at 12-month milestone): Triggered by first signed enterprise contract ≥€500K ACV **and** NAPQES third-party audit report published

---

# XII. APPENDIX: TECHNOLOGY VALIDATION

## NAPQES security properties (per published documentation)

| Property | Status |
|---|---|
| IND-CPA (formal proof) | In progress |
| INT-CTXT | Documented |
| Post-Grover security ~128.5 bits (K=13) | Published |
| Nonce-reuse resistance | ⚠ CVF3: catastrophic — callers must not reuse nonces |
| NIST SP 800-22 randomness (40/40 PASS) | Published |
| TVLA constant-time (Rust, max t=1.134) | Published |
| FIPS 140-3 CMVP | Phase 4, planned |
| Third-party cryptanalytic audit | In progress |
| IETF Internet-Draft | Ready for submission |

## MeshWeave implementation status

| Component | Status |
|---|---|
| Hybrid PQ identity (Ed25519 + ML-DSA-65) | ✓ Complete |
| Self-certifying PeerIDs | ✓ Complete |
| KERI-style key-event log | ✓ Complete |
| OR-Set CRDT ACLs | ✓ Complete |
| LAN UDP multicast discovery | ✓ Complete |
| ChaCha20-Poly1305 tunnel | ✓ Complete |
| ML-KEM-768 PSK rotation | ✓ Complete |
| CLI-to-daemon IPC (Unix / Windows named pipe) | ✓ Complete |
| HTTP management API + web dashboard | ✓ Complete |
| Wide-area Kademlia DHT | Stage 2 (roadmap) |
| Full WireGuard kernel data path | Stage 1 (roadmap) |
| DCUtR hole-punching | Stage 2 (roadmap) |

## Claude Mythos Möbius Bridge — source references

- Anthropic research page: [Discovering cryptographic weaknesses with Claude](https://www.anthropic.com/research/discovering-cryptographic-weaknesses)
- The Hacker News: [Claude AI Just Cracked a Post-Quantum Test Scheme and Found a Faster 7-Round AES Attack](https://thehackernews.com/2026/07/claude-ai-just-cracked-post-quantum.html)
- The Decoder: [Anthropic says its Mythos model found vulnerabilities in cryptographic algorithms that secure the internet](https://the-decoder.com/anthropic-says-its-mythos-model-found-vulnerabilities-in-cryptographic-algorithms-that-secure-the-internet/)
- Cybersecurity News: [Claude Mythos Preview Discovers Cryptographic Weaknesses That Human Experts Missed for Years](https://cybersecuritynews.com/claude-mythos-cryptographic-weaknesses/)
- XenoSpectrum: [Claude Mythos Updates Attack Complexity Estimates for HAWK and 7-Round AES](https://xenospectrum.com/en/claude-mythos-hawk-aes-cryptanalysis/)
- QPulse: [Anthropic's Claude Mythos AI Identifies Theoretical Cryptographic Weaknesses in HAWK and AES](https://qpulse.quasarcybertech.com/news/4873/anthropic-s-claude-mythos-ai-identifies-theoretical-cryptographic-weaknesses-in-hawk-and-aes)

---

*QAegis · Series A Investment Memorandum · July 2026 · Confidential*
*security@quantumaegis.ai · quantumaegis.ai*

*This document contains forward-looking financial projections that are illustrative and not guaranteed. Actual results will differ. This memorandum is provided for discussion purposes only and does not constitute an offer of securities.*
