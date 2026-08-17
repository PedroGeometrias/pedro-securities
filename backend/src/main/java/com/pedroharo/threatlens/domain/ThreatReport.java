package com.pedroharo.threatlens.domain;

import java.time.Instant;
import java.util.List;

// final investigation result, it contais the normalized provide reports and their evidence, a deterministic risk assessment, a comparison with the previus investigation, and it
// have either an Ai generated briefing, given that the keys were provided, or a deterministic briefing
public record ThreatReport(
        String id,
        Indicator indicator,
        RiskAssessment assessment,
        List<ProviderReport> providers,
        String briefing,
        String briefingSource,
        ChangeSummary comparison,
        Instant investigatedAt,
        String integrityHash,
        boolean nativeCoreUsed,
        boolean cachedEvidence
) {}
