package com.pedroharo.threatlens.domain;

import com.fasterxml.jackson.databind.JsonNode;

import java.time.Instant;
import java.util.List;
// this is basically a json normalizer, the idea is, we can take a report from any porvider, but just needing to adapt the normalization pipeline, currently we are only doing OTX and VirusTotal
// but I want to add mre in the future [GREP_THIS_LATER]:wj
public record ProviderReport(
        String provider,
        ProviderStatus status,
        String message,
        int maliciousCount,
        int suspiciousCount,
        int harmlessCount,
        int undetectedCount,
        int pulseCount,
        int reputation,
        String country,
        String asn,
        String networkOwner,
        Instant firstSeen,
        Instant lastSeen,
        List<String> tags,
        List<EvidenceItem> evidence,
        JsonNode raw
) {
    public boolean succeeded() {
        return status == ProviderStatus.SUCCESS;
    }

    public boolean hasPositiveSignals() {
        return maliciousCount > 0 || suspiciousCount > 0 || pulseCount > 0 || reputation < 0;
    }
}
