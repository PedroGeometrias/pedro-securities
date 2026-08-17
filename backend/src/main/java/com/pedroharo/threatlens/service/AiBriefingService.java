package com.pedroharo.threatlens.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.pedroharo.threatlens.config.ThreatLensProperties;
import com.pedroharo.threatlens.domain.ChangeSummary;
import com.pedroharo.threatlens.domain.Indicator;
import com.pedroharo.threatlens.domain.ProviderReport;
import com.pedroharo.threatlens.domain.RiskAssessment;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

// this is meant to give an AI analisys over a deter
@Service
public class AiBriefingService {
    private static final Logger log = LoggerFactory.getLogger(AiBriefingService.class);

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final ThreatLensProperties properties;
    // this is the prompt we are gonna use, it's nothing crazy, and the models that I tested were pretty bad but it worked kinda
    String prompt = """
            Analyze the evidence JSON. Assign exactly ONE verdict: HIGH_RISK, SUSPICIOUS, NO_KNOWN_THREAT, or INCONCLUSIVE.

            Output plain text (no markdown):
            Verdict: [Verdict]
            Evidence: [1-sentence summary of provider votes, reputation, tags]
            Action: [Specific follow-up or "None"]

            Rules:
            - HIGH_RISK: any maliciousCount > 0 OR reputation < 30.
            - SUSPICIOUS: any suspiciousCount > 0 OR reputation 30–70.
            - NO_KNOWN_THREAT: all malicious=0, suspicious=0, reputation > 70.
            - INCONCLUSIVE: < 2 providers, conflicting data, or unclear signal.

            If all signals zero, output exactly: "Verdict: NO_KNOWN_THREAT. Evidence: No provider flags. Action: None."
            Never say "safe". Don't invent data.
            """;
    public AiBriefingService(HttpClient httpClient,
                             ObjectMapper objectMapper,
                             ThreatLensProperties properties) {
        this.httpClient = httpClient;
        this.objectMapper = objectMapper;
        this.properties = properties;
    }

    // generating the prompt
    public String generate(Indicator indicator,
                           RiskAssessment assessment,
                           List<ProviderReport> providers,
                           ChangeSummary comparison) {
        if (!properties.ai().enabled() || properties.ai().apiKey().isBlank()) return null;

        try {
        	// falting the domain object into a simple map, this is so we only send data that the AI needs, keeping the token usage low 
            Map<String, Object> compact = new LinkedHashMap<>();
            compact.put("indicator", indicator);
            compact.put("assessment", assessment);
            compact.put("providers", providers.stream().map(provider -> Map.of(
                    "name", provider.provider(),
                    "status", provider.status(),
                    "malicious", provider.maliciousCount(),
                    "suspicious", provider.suspiciousCount(),
                    "pulses", provider.pulseCount(),
                    "reputation", provider.reputation(),
                    "tags", provider.tags(),
                    "message", provider.message()
            )).toList());
            compact.put("change", comparison);

            // building the JSON request body
            ObjectNode requestBody = objectMapper.createObjectNode();
            requestBody.put("model", properties.ai().model());
            requestBody.put("instructions", prompt);
            requestBody.put("input", objectMapper.writeValueAsString(compact));
            requestBody.put("max_output_tokens", 600);
            requestBody.put("store", false);

            // sending the HTTP request
            HttpRequest request = HttpRequest.newBuilder(
                            URI.create(properties.ai().baseUrl() + "/v1/responses"))
                    .timeout(properties.ai().timeout())
                    .header("Authorization", "Bearer " + properties.ai().apiKey())
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(
                            objectMapper.writeValueAsString(requestBody), StandardCharsets.UTF_8))
                    .build();
            HttpResponse<String> response = httpClient.send(request,
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (response.statusCode() < 200 || response.statusCode() >= 300) {
                log.warn("AI briefing provider returned HTTP {}", response.statusCode());
                return null;
            }
            // parsing the response
            JsonNode root = objectMapper.readTree(response.body());
            for (JsonNode output : root.path("output")) {
                for (JsonNode content : output.path("content")) {
                    if ("output_text".equals(content.path("type").asText())) {
                        String text = content.path("text").asText("").trim();
                        if (!text.isBlank()) return text;
                    }
                }
            }
        } catch (Exception exception) {
            if (exception instanceof InterruptedException) Thread.currentThread().interrupt();
            log.warn("AI briefing failed; deterministic briefing will be used", exception);
        }
        return null;
    }
}
