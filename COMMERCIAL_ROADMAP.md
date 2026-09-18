# VERITAS — Commercial Roadmap

> **VERITAS** — **V**erified **E**PR **R**ecycling with **I**ntegrity **T**amper-proof **A**rrival **S**ignatures
> Open-source community project.

What this file is: the research-backed answer to "what more can be built here, and what's actually wrong or missing, to make this commercial-grade rather than a hackathon demo." `SKILL.md` has the non-negotiable technical invariants; `BUILD_INSTRUCTIONS.md` has the phase-by-phase build order; this file has the market/regulatory context and the full backlog those two are built against.

Regulatory specifics move fast in this space — verify anything load-bearing against the live CPCB portal and MoEFCC notifications before it drives a compliance decision.

---

## 1. Why this is defensible as a commercial product, not just a hackathon pitch

Several well-funded digital platforms already operate in this exact space:

- **Recykal** — a large EPR fulfilment platform used by 650+ brands, claiming over 3 million MT of waste "channelised," with a verified-recycler network and digital documentation/audit support.
- **EcoEx** — a B2B marketplace for waste raw materials and plastic credit certificates, founded 2020.
- **ReCircle (ClimaOne platform)** — aggregates collection/processing and sells EPR credits, with its own collection/sorting facilities and partner sites across India.
- **Recity** — an EPR digital governance platform pitched at municipal-scale plastic waste programs.

What all four of these share: they digitize the *paperwork and marketplace* layer — vendor verification, certificate trading, compliance filings — on top of **self-reported** facility data. None of them puts an independent, tamper-evident sensor at the facility gate. That's the exact gap policy researchers have flagged: a widely cited government-facing policy analysis names "AI, blockchain, and GPS-based tracking" as the way forward for "real-time monitoring and reduc[ing] fraud in EPR certificate trading and waste flow verification" — which is precisely TrustPod's mechanism, not a marketplace feature.

**Positioning:** TrustPod is not a competitor to Recykal/EcoEx/ReCircle — it's infrastructure those platforms (or CPCB itself) could sit on top of. The commercial story is "we make the certificate trustworthy," not "we're another certificate marketplace."

## 2. Regulatory landscape (as of this research pass, 2026)

- **Plastic Waste Management (Amendment) Rules, 2026** (G.S.R. 237(E), 31 March 2026): mandatory recycled-content targets by packaging category, phased reuse targets for rigid packaging (e.g., 70% reuse for large water carboys), a three-year shortfall carry-forward (at least one-third cleared annually), and tiered environmental compensation (₹5,000/₹10,000/₹20,000 per tonne for successive years of shortfall).
- **QR/barcode traceability mandate** on plastic packaging, effective January 2025, requiring the PIBO's name and CPCB registration number to be traceable from the pack.
- **EPR scope expansion, effective 1 April 2026**, to non-ferrous metal scrap (aluminium, copper, zinc and alloys) and construction & demolition waste — a second, larger addressable market for the same physical-verification mechanism, since weighbridge fraud isn't plastic-specific.
- **Customs enforcement**: CBIC blocks customs clearance for importers without valid EPR registration (since July 2025) — this is a strong lever for demanding verified certificates on the import side, not just the recycler side.
- **Penalties**: Section 15 of the Environment (Protection) Act, 1986 allows prosecution up to 5 years imprisonment or ₹1 lakh/day for willful non-compliance; separate reported enforcement actions have run into crore-level compensation for individual EPR lapses.
- **Take-away for the architecture**: don't hard-code "plastic" anywhere load-bearing. Waste category, unit of measure, and the applicable target/compensation schedule should all be configuration, not assumptions — the metals and C&D expansion is happening now, and a product that can only speak "plastic tonnage" will need a rewrite instead of a config change to capture it.

## 3. Hardware/crypto decision, at commercial scale

Restating and expanding `SKILL.md`'s hardware section with the sourcing angle:

| Option | Crypto | Certification | Honest framing | When to use |
|---|---|---|---|---|
| A — ATECC608-family | ECDSA P-256 (hardware) | Not independently verified here; both A and B revisions are marked "Not Recommended for New Designs" on Microchip's own product pages | "Hardware-backed ECDSA," never "hardware Ed25519" | Cheapest path if you're willing to build on a part line Microchip is sunsetting — check their current recommended replacement before committing a commercial BOM |
| B — Software Ed25519 | Ed25519 (software, flash-encrypted) | None | Never claim "hardware-backed" | Prototype/demo only |
| C — NXP EdgeLock SE050 (B/C-series) | Ed25519/EdDSA (hardware, native) | Common Criteria EAL6+, FIPS 140-2 Level 3 | "Hardware-backed Ed25519" is actually true | Recommended default for a commercial device — resolves the crypto/BOM contradiction the earlier review caught |

Don't source per-unit pricing from memory — get current distributor quotes (Mouser/DigiKey/Future Electronics) for whichever SKU is chosen before it goes into a pitch deck's cost-per-pod line, since secure-element pricing and part availability shift.

## 4. Full commercial feature backlog, by category

This is deliberately broader than any one hackathon build — treat it as a menu to prioritize from with the user, not a mandate to build all of it.

**Core verification (hardening the existing pitch)**
- Real signature verification, atomic minting, working fraud checks, real ledger (already invariants 1–7 in `SKILL.md`)
- Computer-vision cross-check of photographed load against claimed material category
- GPS-backed circular-trucking detection, with ANPR as a stretch goal
- Cross-facility collusion detection (same operator entity, correlated timing across multiple "independent" facilities)

**Compliance & regulatory integration**
- CPCB portal export/integration layer, kept honest about live-vs-manual-export status
- Packaging-level QR/barcode issuance matching the January 2025 mandate
- Configurable waste-category schedules so plastics, e-waste, and the 2026-onward metals/C&D categories share one engine
- Auditor-facing, role-scoped export tooling

**Trust & security**
- Signed firmware OTA
- Secrets management / KMS
- Rate-limited, request-signed ingestion endpoints
- A written security posture doc, with ISO/IEC 27001 and SOC 2 Type II as a stated (not yet claimed) roadmap
- DPDP Act, 2023-aware data minimization and retention policy for photos/plate data

**Multi-tenancy & access**
- Role-based auth (facility operator / admin / read-only regulator)
- Tenant data isolation enforced at the query layer
- Append-only audit log for all certificate-relevant actions

**Field & mobile**
- Auditor mobile app for on-site QR scan → verification proof lookup
- Facility-operator mobile view for sites without a desktop workstation
- Hindi/regional-language UI for gate-level operator staff

**Ops & scale**
- Containerized deployment, IaC
- Object storage for photos, Postgres with read replicas
- A queue between ingestion and the mint/fraud pipeline so throughput isn't gated by fraud-check latency
- Metrics + alerting on fraud-flag spikes and facility silence

**Business layer**
- Pricing model decision (per-device vs. per-tonne-verified vs. hybrid)
- Facility onboarding flow, SLAs, billing integration
- A concrete pilot plan with a named partner facility and a measurable success criterion

## 5. Suggested sequencing

1. Finish the core (`BUILD_INSTRUCTIONS.md` Phases 0–10) with all seven core invariants genuinely holding — this is what a pilot conversation needs, and it's also the foundation everything commercial sits on.
2. Add auth/tenancy and the regulator export layer (Phases 11–12) before adding CV or mobile — a commercial pilot partner will ask "who else can see my data" before they ask "can it detect a mislabeled load."
3. Layer in CV/circular-trucking hardening and security/compliance posture (Phases 13–17) once there's a real pilot to harden against, not speculatively.
4. Ops, business layer, and pilot packaging (Phases 18–20) run alongside actual pilot conversations, not before them.

## 6. What's still needed to make this real (not a documentation gap — an information gap)


- **The actual project source** — no zip or repo has come through in this conversation, only pasted transcript text describing prior work. Everything in these three files is a fresh plan, not a diff against real code.
- **A target pilot facility or state**, if one exists yet — the regulatory and market notes above are national-level; a real pilot plan (Phase 20) needs a specific SPCB/facility context to be concrete rather than generic.
- **A rough unit-economics target for the pod itself** (cost ceiling per device), since that's what actually decides between the Option A/B/C hardware path in section 3, not just the crypto-purity argument.

## Sources consulted for this pass

- Plastic Waste Management (Amendment) Rules, 2026 coverage: drishtiias.com, corporateprofessionals.com, greensutra.in, afleo.com, studyiq.com, avigroup.in, pakka.com, diligencecertification.com
- Secure element datasheets/product pages: microchip.com (ATECC608A, ATECC608B, ATECC608B-TCSM, ATECC608B-TNGTLS), nxp.com (SE050 family / EdgeLock)
- Competitive landscape: recykal.com, renewablematter.eu (EcoEx), gsma.com (ReCircle/ClimaOne), npcindia.gov.in (Recity), pmfias.com (policy analysis on blockchain/GPS as fraud countermeasures)
- EPR policy references: cpcb.nic.in (Central Pollution Control Board India)
