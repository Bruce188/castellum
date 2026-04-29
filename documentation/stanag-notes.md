# NATO Terminology Notes — AAP-31 and NCIRC Context

**Version:** 1.0 (Feature 10)
**Date:** 2026-04-29

---

> **Citation honesty disclaimer:** This document is not based on restricted-circulation directive text. Alignment with NATO standards is aspirational, based on public NATO communications, published academic references, and publicly available NATO glossary materials. No claim of compliance with any restricted NATO directive is made here. The AC/322-D/0048 directive text is restricted-circulation and has not been consulted. References to NCIRC and AC/322 draw only on materials available via the NATO public website and open academic literature.

---

## Purpose

Castellum is described as a "NATO-track" tool — meaning it is designed with NATO operational concepts in mind and uses vocabulary that can be aligned with NATO standards. This document records that alignment honestly: where Castellum vocabulary matches NATO usage, where it diverges, and where alignment is aspirational rather than achieved.

The audience for this document is a security reviewer who needs to evaluate whether Castellum can be integrated into a NATO-aligned SOC or NCIRC workflow, or a developer who wants to understand what NATO terminology concepts map to Castellum's internal model.

---

## AAP-31 Terminology Cross-Walk

AAP-31 is the Allied Administrative Publication 31: "NATO Glossary of Communication and Information Systems Terms and Definitions." It provides the authoritative NATO vocabulary for CIS (Communication and Information Systems) concepts. The edition referenced here is the publicly cited edition; the precise edition number is not guaranteed from public sources.

Castellum's vocabulary is derived primarily from OWASP (Open Web Application Security Project) and STRIDE/MITRE ATT&CK conventions, which are common in commercial and academic security tooling but differ from NATO CIS vocabulary in several areas.

| Castellum term | NATO AAP-31 equivalent (public summary) | Alignment | Notes |
|---------------|----------------------------------------|-----------|-------|
| `Device` (entity in the device inventory table) | "node" or "CIS element" | Partial | AAP-31 uses "node" for a logical addressable entity within a network. Castellum's "device" is broader — it encompasses physical hosts, virtual machines, and OT endpoints. Close enough for practical alignment; no rename proposed. |
| `Service` (network-service row; port + protocol) | "service" or "network service" | Strong | NATO usage of "network service" matches Castellum's model directly. |
| `Vulnerability` (CVE-linked finding) | "vulnerability" | Strong | Both use the same term with compatible definitions. NIST NVD and NATO vulnerability databases use the same CVE identifiers. |
| `Indicator` (threat-intel export object) | "indicator of compromise (IoC)" | Partial | Castellum exports STIX 2.1 `indicator` objects. NATO threat-sharing guidance references IoC concepts compatible with STIX. AAP-31 may use "incident indicator" in some contexts — review against current edition for precision. |
| `Scan` (active network scan job) | "active reconnaissance" or "probing" | Conceptual | NATO operational vocabulary distinguishes active from passive collection. Castellum's "scan" maps to active reconnaissance in NATO operational language. |
| `Discovery` (passive discovery via ARP/mDNS) | "passive collection" or "passive sensing" | Conceptual | Passive ARP cache monitoring and mDNS listening map to passive collection concepts in NATO intelligence collection doctrine. |
| `Risk score` (composite CVSS+EPSS+KEV+criticality) | No direct AAP-31 equivalent | Gap | NATO vulnerability management frameworks reference severity and priority but do not define a specific composite scoring formula equivalent to Castellum's. The concept is compatible; the specific formula is a Castellum extension. |
| `Attack graph` (JGraphT shortest-path exploit chain) | "attack vector" (partial) | Partial | NATO doctrine uses "attack vector" in a narrower sense (initial access method). Castellum's attack graph is broader — it models multi-hop lateral movement chains. No direct AAP-31 equivalent for the full graph concept. |
| `Audit log` (append-only operation record) | "event log" or "audit trail" | Strong | Compatible. NATO CIS operational guidance uses "audit trail" for the same concept. |
| `ADMIN role` | "privileged user" | Strong | NATO CIS governance distinguishes privileged from standard users. Castellum's ADMIN role maps to the privileged user concept. |

**Mismatches to flag for future alignment work:**

1. **"Device" vs "node"** — if Castellum is used in a NATO CIS integration context, renaming the primary inventory entity from "device" to "node" would align the REST API vocabulary with AAP-31. This is a non-trivial API-breaking change; flagged for future consideration.

2. **"Risk score" has no AAP-31 equivalent** — the composite scoring formula (CVSS × EPSS × KEV × criticality) is a Castellum-specific construct. When presenting risk data to NATO partners, translating the numeric score to a qualitative severity tier (LOW / MEDIUM / HIGH / CRITICAL) and mapping it to NATO threat severity levels would improve interpretability.

3. **"Attack graph" is broader than any single AAP-31 term** — when communicating attack-graph results to NATO audiences, framing the output as an "exploitation chain analysis" or "lateral movement path assessment" may communicate more clearly than using the internal "attack graph" term.

---

## AC/322-D/0048 NCIRC Context

### NATO's Computer Incident Response Capability (NCIRC)

NCIRC — the NATO Computer Incident Response Capability — is NATO's primary cyber incident response organisation. Based on publicly available NATO communications, NCIRC provides 24/7 protection of NATO networks, coordinates with national Computer Emergency Response Teams (CERTs) and CERTs of NATO member nations, and manages information-sharing on cyber threats.

The NATO Communications and Information Agency (NCI Agency) operates NCIRC. NCIRC produces and distributes cyber threat indicators to NATO entities and national partners via established sharing mechanisms.

### AC/322 Committee Context

AC/322 is the NATO C3 Board (Communications and Information Systems Committee). Publicly, the C3 Board is responsible for CIS policy, doctrine, and standards within NATO, including network security directives. The directive AC/322-D/0048 is described in public references as a network defence operations directive. **Its full text is restricted-circulation and has not been consulted for this document.**

The implication for Castellum: if deployed in a NATO-member organisation that is subject to AC/322 directives, the specific requirements of AC/322-D/0048 would govern how network monitoring tools are deployed and how incident data is reported. Castellum's architecture (local deployment, no persistent cloud dependencies, append-only audit log, MISP/TAXII export) is designed to be compatible with the general principles of network defence operations as described in public NATO guidance — but formal AC/322-D/0048 compliance has not been assessed.

### Castellum as NCIRC Integration Point

The most natural integration point between Castellum and an NCIRC-style threat-sharing fabric is the MISP push capability:

```
Castellum device inventory
        +
CVE/EPSS/KEV enrichment
        |
        ▼
STIX 2.1 bundle assembly (BundleAssembler)
        |
        ▼
POST /api/threat-intel/push/misp
        |
        ▼
Organisation MISP instance ─── MISP galaxy sync ───▶ NCIRC sharing fabric
```

MISP (Malware Information Sharing Platform) is explicitly listed in public NCIRC documentation as a supported threat-sharing mechanism for NATO partners. Castellum's `MispClient` pushes STIX-format attributes to a configured MISP instance; that instance can then participate in MISP galaxy or organisation-to-organisation sharing with other NATO-aligned MISP nodes.

For this integration to function:

1. The MISP instance must be configured for federation with the NCIRC network or relevant sharing partner.
2. The Castellum-generated STIX bundle content (device IP ranges, vulnerability IDs, risk scores) must be reviewed for classification before pushing to a shared MISP instance — raw internal network topology data has sensitivity implications.
3. The `MISP_API_KEY` and `MISP_BASE_URL` environment variables in Castellum must point to the organisation's own MISP instance, not directly to any NCIRC infrastructure.

See [documentation/stix-taxii-misp.md](stix-taxii-misp.md) for the full STIX export and MISP push configuration reference.

### TAXII as an Alternative Sharing Path

The TAXII 2.1 push capability (`POST /api/threat-intel/push/taxii`) provides an alternative path to a TAXII-capable sharing server. TAXII (Trusted Automated eXchange of Intelligence Information) is an OASIS standard that is explicitly supported in NATO threat-sharing contexts. If the target sharing infrastructure uses a TAXII 2.1 collection endpoint rather than MISP, Castellum's `TaxiiClient` can push directly.

---

## Out-of-Scope and Limitations

**Restricted text not cited.** The AC/322-D/0048 directive text is restricted-circulation. This document deliberately contains no content derived from it. Any future alignment work that involves restricted directives requires access through proper NATO or national channels, not this document.

**No compliance claim.** Nothing in this document constitutes a claim that Castellum complies with AC/322-D/0048, NCIRC operational requirements, or any other NATO directive. Alignment is aspirational. An organisation deploying Castellum in a NATO-regulated context must conduct its own assessment against the applicable restricted directives.

**AAP-31 edition uncertainty.** Public references do not always specify which edition of AAP-31 is current. The cross-walk above is based on the general and publicly cited content of AAP-31 as a NATO glossary. A formal alignment review should confirm against the current edition obtained through official NATO channels.

**Vocabulary evolution.** NATO CIS vocabulary evolves through the C3 Board and AAP-31 update cycles. The cross-walk above should be reviewed and updated periodically, particularly when Castellum's REST API vocabulary or data model changes.

---

## Cross-References

| Document | Relevance |
|----------|-----------|
| [documentation/stix-taxii-misp.md](stix-taxii-misp.md) | STIX 2.1 export format, TAXII/MISP push configuration, audit trail |
| [documentation/threat-model.md](threat-model.md) | Full threat model including export module threat analysis |
| [documentation/compliance.md](compliance.md) | NIST 800-53 mapping — the compliance framework complementing this NATO alignment note |
