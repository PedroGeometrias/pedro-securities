package com.pedroharo.threatlens.api;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pedroharo.threatlens.domain.ThreatReport;
import com.pedroharo.threatlens.history.InvestigationRepository;
import com.pedroharo.threatlens.service.InvestigationService;
import com.pedroharo.threatlens.service.ReportSigningService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.Map;

@RestController
@RequestMapping("/api")
// translates HTTP requests into JAVA methodss calls, and vice versa, using the methods create in this program
public class InvestigationController {
    private final InvestigationService investigationService;
    private final InvestigationRepository repository;
    private final ReportSigningService signingService;
    private final ObjectMapper objectMapper;

    // constructor
    public InvestigationController(InvestigationService investigationService,
                                   InvestigationRepository repository,
                                   ReportSigningService signingService,
                                   ObjectMapper objectMapper) {
        this.investigationService = investigationService;
        this.repository = repository;
        this.signingService = signingService;
        this.objectMapper = objectMapper;
    }

    // takes a request, and wraps it around java stuff, and calls investigate from service on that
    // exposing POST /api/investigations
    @PostMapping("/investigations")
    public ThreatReport investigate(@Valid @RequestBody SearchRequest request) {
        return investigationService.investigate(request.value(), request.forceRefresh());
    }

    // this expects a multipart file upload, exposes POST /api/investigations/file, HTTP requests containt
    // multiple independent sections called parts, we only want the part that is called file here
    @PostMapping(value = "/investigations/file", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ThreatReport investigateFile(@RequestPart("file") MultipartFile file,
                                        @RequestParam(defaultValue = "false") boolean forceRefresh)
            throws IOException {
        if (file.isEmpty()) throw new IllegalArgumentException("Choose a non-empty file to hash.");
        return investigationService.investigateFile(file.getInputStream(),
                file.getOriginalFilename(), forceRefresh);
    }

    // tries to find the investigation from an id, if id is invalid, we throw an error
    @GetMapping("/investigations/{id}")
    public ThreatReport find(@PathVariable String id) {
        return repository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Investigation not found: " + id));
    }

    @GetMapping(value = "/investigations/{id}/export", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<byte[]> export(@PathVariable String id) throws JsonProcessingException {
        ReportSigningService.ExportEnvelope envelope = signingService.export(id);
        byte[] body = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsBytes(envelope);
        String filename = "threatlens-report-" + id.substring(0, Math.min(8, id.length())) + ".json";
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        ContentDisposition.attachment().filename(filename).build().toString())
                .contentType(MediaType.APPLICATION_JSON)
                .body(body);
    }

    @PostMapping("/reports/verify")
    public Map<String, Object> verify(@Valid @RequestBody VerifyRequest request) {
        boolean valid = signingService.verify(request.payload(), request.signature());
        return Map.of("valid", valid,
                "message", valid ? "RSA-PSS signature is valid." : "Signature is invalid or signing is unavailable.");
    }

    public record SearchRequest(@NotBlank(message = "Indicator is required") String value,
                                boolean forceRefresh) {}

    public record VerifyRequest(JsonNode payload,
                                @NotBlank(message = "Signature is required") String signature) {}
}
