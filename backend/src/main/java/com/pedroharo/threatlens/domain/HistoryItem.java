package com.pedroharo.threatlens.domain;

import java.time.Instant;

// ligh weight summary of a save threadreport, this is meant only for the history list:w
public record HistoryItem(
        String id,
        String indicator,
        String normalizedIndicator,
        IndicatorType indicatorType,
        RiskVerdict verdict,
        int riskScore,
        int providerCount,
        Instant createdAt,
        String briefing,
        String integrityHash
) {}
