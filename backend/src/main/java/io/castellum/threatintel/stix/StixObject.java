package io.castellum.threatintel.stix;

public sealed interface StixObject
    permits StixIndicator, StixVulnerability, StixInfrastructure, StixRelationship, StixIdentity {
    String id();
}
