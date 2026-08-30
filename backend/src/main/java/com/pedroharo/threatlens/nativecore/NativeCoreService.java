package com.pedroharo.threatlens.nativecore;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pedroharo.threatlens.config.ThreatLensProperties;
import com.pedroharo.threatlens.domain.Indicator;
import com.pedroharo.threatlens.domain.IndicatorType;
import com.pedroharo.threatlens.domain.RiskAssessment;
import com.pedroharo.threatlens.domain.RiskVerdict;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/*
 * this class makes the C code that I wrote , behave like a normal java @Service
 */

// @Service is weird because it tells Spring to crate and mage one instance of this class
@Service
public class NativeCoreService {
	// creating a log obj, usin LoggerFactory, that basically get all the logs from this class
    private static final Logger log = LoggerFactory.getLogger(NativeCoreService.class);

    private final ThreatLensProperties properties;
    private final ObjectMapper objectMapper;
    private final Path executable;
    private volatile boolean available;

    // properties: path, timeout, if C is required or not, etc
    // objectMapper converts JSON produced by C into java data
    public NativeCoreService(ThreatLensProperties properties, ObjectMapper objectMapper) {
        this.properties = properties;
        this.objectMapper = objectMapper;
        this.executable = Path.of(properties.nativeCore().path()).toAbsolutePath().normalize();
    }

    // checking if the utility is available or not, post construct means that spring will call this after the obj is created, so we can check
    // if it's available later and throw errors if not
    @PostConstruct
    void validateAvailability() {
        available = Files.isRegularFile(executable) && Files.isExecutable(executable);
        if (!available && properties.nativeCore().required()) {
            throw new NativeCoreException("Required native core is not executable at " + executable);
        }
        if (!available) {
            log.warn("Native core unavailable at {}; calls will fail", executable);
        }
    }

    // quick getter so other parts of the app know if we can use native code or not
    public boolean isAvailable() {
        return available;
    }

    // turning user input into a indicator
    public Indicator classify(String value) {
        if (!available) {
            throw new NativeCoreException("Native core is unavailable");
        }
        try {
            JsonNode result = objectMapper.readTree(run(List.of("classify", value), null, true));
            if (!result.path("valid").asBoolean(false)) {
                throw new IllegalArgumentException("Enter a valid IPv4, IPv6, domain, MD5, SHA-1, or SHA-256 indicator.");
            }
            return new Indicator(value, result.path("normalized").asText(),
                    IndicatorType.valueOf(result.path("type").asText()));
        } catch (NativeCoreException e) {
            available = false;
            log.error("Native core failed during classification; marking unavailable", e);
            throw e;
        } catch (IOException e) {
            throw new NativeCoreException("Native classifier returned malformed data", e);
        }
    }

    // using my hash in c
    public String hash(InputStream input) {
        if (!available) {
            throw new NativeCoreException("Native core is unavailable");
        }
        try {
            return run(List.of("hash", "--stdin"), input, false).trim();
        } catch (NativeCoreException e) {
            available = false;
            log.error("Native core failed during hashing; marking unavailable", e);
            throw e;
        }
    }

    public String hash(byte[] input) {
        return hash(new ByteArrayInputStream(input));
    }

    // calculating risk result, using my acess function
    public RiskAssessment assess(int otxPulses,
                                 int vtMalicious,
                                 int vtSuspicious,
                                 int reputation,
                                 int successfulProviders,
                                 boolean recentActivity) {
        if (!available) {
            throw new NativeCoreException("Native core is unavailable");
        }
        // converting everything into command line argument
        List<String> arguments = List.of(
                "assess",
                Integer.toString(otxPulses),
                Integer.toString(vtMalicious),
                Integer.toString(vtSuspicious),
                Integer.toString(reputation),
                Integer.toString(successfulProviders),
                recentActivity ? "1" : "0"
        );
        try {
            JsonNode result = objectMapper.readTree(run(arguments, null, false));
            List<String> reasons = new ArrayList<>();
            result.path("reasons").forEach(reason -> reasons.add(reason.asText()));
            return new RiskAssessment(
                    result.path("score").asInt(),
                    RiskVerdict.valueOf(result.path("verdict").asText()),
                    reasons);
        } catch (NativeCoreException e) {
            available = false;
            log.error("Native core failed during risk assessment; marking unavailable", e);
            throw e;
        } catch (IOException e) {
            throw new NativeCoreException("Native assess returned malformed data", e);
        }
    }

    // sign a payload using the C code and the private key from config
    public String sign(byte[] payload) {
        if (!available) {
            throw new NativeCoreException("Native core is unavailable; report cannot be signed");
        }
        return run(List.of("sign", properties.signing().privateKeyPath(), "--stdin"),
                new ByteArrayInputStream(payload), false).trim();
    }

    // verify a signature with the C code and public key, returns true only if output is "valid"
    public boolean verify(byte[] payload, String signature) {
        if (!available) {
            throw new NativeCoreException("Native core is unavailable; signature cannot be verified");
        }
        try {
            String output = run(List.of("verify", properties.signing().publicKeyPath(), signature, "--stdin"),
                    new ByteArrayInputStream(payload), true);
            return "valid".equals(output.trim());
        } catch (NativeCoreException e) {
            return false;
        }
    }

    // real C to java bridge
    private String run(List<String> arguments, InputStream input, boolean allowNonZero) {
        // building the command
        List<String> command = new ArrayList<>(arguments.size() + 1);
        command.add(executable.toString());
        command.addAll(arguments);

        // creating a new process for that especific binary
        try {
            Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
            if (input != null) {
                try (var output = process.getOutputStream(); input) {
                    input.transferTo(output);
                }
            } else {
                process.getOutputStream().close();
            }

            boolean finished = process.waitFor(properties.nativeCore().timeout().toMillis(), TimeUnit.MILLISECONDS);
            if (!finished) {
                process.destroyForcibly();
                throw new NativeCoreException("Native core timed out");
            }
            String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            if (process.exitValue() != 0 && !allowNonZero) {
                throw new NativeCoreException("Native core failed: " + output.trim());
            }
            return output;
        } catch (IOException e) {
            throw new NativeCoreException("Unable to execute native core", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new NativeCoreException("Native core execution interrupted", e);
        }
    }
}
