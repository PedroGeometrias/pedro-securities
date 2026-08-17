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
import java.net.Inet6Address;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

/*
 * this class makes the C code that I wrote , behave like a normal java @Service
 */

// @Service is weird because it tells Spring to crate and mage one instance of this class
@Service
public class NativeCoreService {
	// creating a log obj, usin LoggerFactory, that basically get all the logs from this class
    private static final Logger log = LoggerFactory.getLogger(NativeCoreService.class);
    // we use regex for domains and Hex
    private static final Pattern HEX = Pattern.compile("^[0-9a-fA-F]+$");
    private static final Pattern DOMAIN = Pattern.compile(
            "^(?=.{1,253}\\.?$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.?$");

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
    // if it's available later, then we can use fallbacks made with java code
    @PostConstruct
    void validateAvailability() {
        available = Files.isRegularFile(executable) && Files.isExecutable(executable);
        if (!available && properties.nativeCore().required()) {
            throw new NativeCoreException("Required native core is not executable at " + executable);
        }
        if (!available) {
            log.warn("Native core unavailable at {}; Java safety fallback is active", executable);
        }
    }

    // quick getter so other parts of the app know if we can use native code or not
    public boolean isAvailable() {
        return available;
    }

    // turning user input into a indicator
    public Indicator classify(String value) {
        if (available) {
            try {
                JsonNode result = objectMapper.readTree(run(List.of("classify", value), null, true));
                if (!result.path("valid").asBoolean(false)) {
                    throw new IllegalArgumentException("Enter a valid IPv4, IPv6, domain, MD5, SHA-1, or SHA-256 indicator.");
                }
                return new Indicator(value, result.path("normalized").asText(),
                        IndicatorType.valueOf(result.path("type").asText()));
            } catch (NativeCoreException exception) {
                disableAfterFailure(exception);
            } catch (IOException exception) {
                throw new NativeCoreException("Native classifier returned malformed data", exception);
            }
        }
        // if native is off or fails, use the Java fallback that does the same classification
        return classifyInJava(value);
    }
    // using my hash in c 
    public String hash(InputStream input) {
        if (available) {
            try {
                return run(List.of("hash", "--stdin"), input, false).trim();
            } catch (NativeCoreException exception) {
                disableAfterFailure(exception);
                throw exception;
            }
        }
        // if for some reason we don't have the C hashing functions 
        return hashInJava(input);
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
                                 boolean recentActivity){
    	// converting everything into command line argument
        if (available) {
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
                return new RiskAssessment(result.path("score").asInt(),
                        RiskVerdict.valueOf(result.path("verdict").asText()), reasons);
            } catch (IOException | NativeCoreException exception) {
                disableAfterFailure(exception);
            }
        }
        // if we don't have the function for some reason, we fallback to java with the same algo
        return assessInJava(otxPulses, vtMalicious, vtSuspicious, reputation,
                successfulProviders, recentActivity);
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
        } catch (NativeCoreException exception) {
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
        } catch (IOException exception) {
            throw new NativeCoreException("Unable to execute native core", exception);
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new NativeCoreException("Native core execution interrupted", exception);
        }
    }

    // if native fails and it's required we rethrow, otherwise we mark unavailable and use fallback
    private void disableAfterFailure(Exception exception) {
        if (properties.nativeCore().required()) {
            throw exception instanceof NativeCoreException nativeException
                    ? nativeException
                    : new NativeCoreException("Native core failed", exception);
        }
        available = false;
        log.error("Native core failed; switching to Java fallback", exception);
    }

    // this is the Java fallback classifier, used when the C binary is not there or failed
    private static Indicator classifyInJava(String submitted) {
        if (submitted == null) {
            throw new IllegalArgumentException("Indicator is required.");
        }
        String value = submitted.trim();
        // check for hash lengths (32 MD5, 40 SHA1, 64 SHA256) and pure hex
        if ((value.length() == 32 || value.length() == 40 || value.length() == 64)
                && HEX.matcher(value).matches()) {
            IndicatorType type = value.length() == 32 ? IndicatorType.MD5
                    : value.length() == 40 ? IndicatorType.SHA1 : IndicatorType.SHA256;
            return new Indicator(submitted, value.toLowerCase(Locale.ROOT), type);
        }
        // if it has a colon, try to parse as IPv6
        if (value.contains(":")) {
            try {
                InetAddress address = InetAddress.getByName(value);
                if (address instanceof Inet6Address) {
                    return new Indicator(submitted, address.getHostAddress(), IndicatorType.IPV6);
                }
            } catch (Exception ignored) {
                // Continue to the validation error below.
            }
        }
        // manual IPv4 check
        if (isIpv4(value)) {
            return new Indicator(submitted, value, IndicatorType.IPV4);
        }
        // domain validation and normalization
        if (DOMAIN.matcher(value).matches()) {
            String normalized = value.endsWith(".") ? value.substring(0, value.length() - 1) : value;
            return new Indicator(submitted, normalized.toLowerCase(Locale.ROOT), IndicatorType.DOMAIN);
        }
        throw new IllegalArgumentException("Enter a valid IPv4, IPv6, domain, MD5, SHA-1, or SHA-256 indicator.");
    }

    // manual IPv4 validation without using InetAddress, because InetAddress can be too lenient
    private static boolean isIpv4(String value) {
        String[] parts = value.split("\\.", -1);
        if (parts.length != 4) return false;
        for (String part : parts) {
            if (part.isEmpty() || part.length() > 3 || !part.chars().allMatch(Character::isDigit)) return false;
            if (part.length() > 1 && part.charAt(0) == '0') return false;
            if (Integer.parseInt(part) > 255) return false;
        }
        return true;
    }

    // Java fallback hashing using SHA-256, streams the input so we don't load huge files into memory
    private static String hashInJava(InputStream input) {
        try (input) {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] buffer = new byte[16 * 1024];
            int count;
            while ((count = input.read(buffer)) >= 0) {
                digest.update(buffer, 0, count);
            }
            return HexFormat.of().formatHex(digest.digest());
        } catch (IOException | NoSuchAlgorithmException exception) {
            throw new NativeCoreException("Unable to hash input", exception);
        }
    }

    // Java fallback risk scoring, same algorithm as the C version
    private static RiskAssessment assessInJava(int otxPulses,
                                               int vtMalicious,
                                               int vtSuspicious,
                                               int reputation,
                                               int successfulProviders,
                                               boolean recentActivity) {
        int score = 0;
        int positiveSources = 0;
        List<String> reasons = new ArrayList<>();
        // each source that says bad stuff adds points and a reason
        if (vtMalicious > 0) {
            score += Math.min(60, vtMalicious * 10);
            reasons.add("VT_MALICIOUS_ENGINES");
            positiveSources++;
        }
        if (vtSuspicious > 0) {
            score += Math.min(20, vtSuspicious * 5);
            reasons.add("VT_SUSPICIOUS_ENGINES");
        }
        if (otxPulses > 0) {
            score += Math.min(40, otxPulses * 8);
            reasons.add("OTX_PULSE_MATCHES");
            positiveSources++;
        }
        if (reputation < 0) {
            score += Math.min(15, -reputation);
            reasons.add("NEGATIVE_COMMUNITY_REPUTATION");
        }
        // if two or more providers agree, that's worth extra points
        if (positiveSources >= 2) {
            score += 10;
            reasons.add("PROVIDER_AGREEMENT");
        }
        // recent activity gives a small boost
        if (recentActivity) {
            score += 5;
            reasons.add("RECENT_ACTIVITY");
        }
        score = Math.min(100, score);

        // now decide the verdict based on score and some hard thresholds
        RiskVerdict verdict;
        if (successfulProviders <= 0) {
            verdict = RiskVerdict.INCONCLUSIVE;
            reasons.add("NO_PROVIDER_DATA");
        } else if (score >= 70 || vtMalicious >= 5 || otxPulses >= 6) {
            verdict = RiskVerdict.HIGH_RISK;
        } else if (score >= 25 || vtMalicious > 0 || vtSuspicious > 0 || otxPulses > 0) {
            verdict = RiskVerdict.SUSPICIOUS;
        } else {
            verdict = RiskVerdict.NO_KNOWN_THREAT;
            reasons.add("NO_POSITIVE_SIGNALS");
        }
        return new RiskAssessment(score, verdict, reasons);
    }
}