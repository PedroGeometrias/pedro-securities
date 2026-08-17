package com.pedroharo.threatlens.service;

import com.pedroharo.threatlens.domain.ChangeSummary;
import com.pedroharo.threatlens.domain.Indicator;
import com.pedroharo.threatlens.domain.ProviderReport;
import com.pedroharo.threatlens.domain.RiskAssessment;
import org.springframework.stereotype.Service;

import java.util.List;

// generating the brief analysis
@Service
public class BriefingService {
    private final DeterministicBriefingService deterministic;
    private final AiBriefingService ai;

    // it can be determinist + ai, or only deterministic
    public BriefingService(DeterministicBriefingService deterministic, AiBriefingService ai) {
        this.deterministic = deterministic;
        this.ai = ai;
    }

    // actually generating it now
    public Result generate(Indicator indicator,
                           RiskAssessment assessment,
                           List<ProviderReport> providers,
                           ChangeSummary comparison) {
    	// if the AI briefing exits, we return it
        String aiBriefing = ai.generate(indicator, assessment, providers, comparison);
        if (aiBriefing != null) {
        	return new Result(aiBriefing, "OpenAI");
        }
        // if not, we return only the deterministic one
        return new Result(deterministic.generate(indicator, assessment, providers, comparison),
                "Deterministic");
    }

    // immutable result
    public record Result(String text, String source) {}
}
