# STIX 2.1 JSON Schemas (bundled)

Source: https://github.com/oasis-open/cti-stix2-json-schemas
Tag: stix2.1
Pinned commit SHA: inline-subset-v1
Last refreshed: 2026-04-29

To refresh from the OASIS upstream: `bash scripts/refresh-stix-schemas.sh`.

Used by `StixSchemaValidator` (test scope only). Not bundled in production jar.

## Note on inline subset

This schema directory contains a hand-maintained subset of the OASIS STIX 2.1
JSON schemas sufficient for validating `bundle`, `identity`, `indicator`,
`vulnerability`, `infrastructure`, and `relationship` SDOs as produced by
`BundleAssembler`. The full OASIS schema set can be fetched via
`scripts/refresh-stix-schemas.sh` (requires network access).

The inline subset was chosen because outbound HTTP is not available in the
CI pipeline environment. The subset covers all object types emitted by
`BundleAssembler`; no SDO type outside this set is currently generated.
