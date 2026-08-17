package com.pedroharo.threatlens.provider;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.NullNode;
import com.pedroharo.threatlens.config.ThreatLensProperties;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;

// this class provides a way to make HTTP GET to external api's, it handles JSON and timeouts too
@Component
public class ExternalApiClient {
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final Duration timeout;

    // basic constructor logic
    public ExternalApiClient(HttpClient httpClient,
                             ObjectMapper objectMapper,
                             ThreatLensProperties properties) {
        this.httpClient = httpClient;
        this.objectMapper = objectMapper;
        this.timeout = properties.providers().timeout();
    }
    // this is the get implementation, it takes:
    // url -> full endpoint URL
    // header -> additional HTTP headers
    public ApiResponse get(String url, Map<String, String> headers) {
    	// creates a GET with a give url
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(url))
                .GET()
                .timeout(timeout)
                .header("Accept", "application/json")
                .header("User-Agent", "ThreatLens/1.0 (+https://github.com/pedrogeometrias)");
        headers.forEach((name, value) -> builder.header(name, value));
        HttpRequest request = builder.build();

        // this is a retry loop, it tries to build the request 2 times, one is the intial time, and another is a retry
        for (int attempt = 0; attempt < 2; ++attempt) {
            try {
            	// sends the request, saves that into a respons, everything is treated as a String in format UTF_*
                HttpResponse<String> response = httpClient.send(request,
                        HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
                // saves the status code of the response, so we can do the retry loop
                int status = response.statusCode();
                // here we check the status, if it is a error, we try another time
                if ((status == 429 || status >= 500) && attempt == 0) { 
                    Thread.sleep(500L);
                    continue;
                }
                // we gonna parse the JSON body now
                JsonNode body;
                try {
                	// if the body is blank, we set it to NULL, if not, we try to parse that bad boy, if the parsing fails, we also make it NULL
                    body = response.body().isBlank() ? NullNode.getInstance()
                            : objectMapper.readTree(response.body());
                    
                }
                catch (IOException ignored) {
                    body = NullNode.getInstance();
                }
                // we return the correct response
                return new ApiResponse(status, body, response.body());
            } catch (IOException exception) {
                if (attempt == 1) {
                    throw new ProviderCallException("Provider request failed", exception);
                }
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
                throw new ProviderCallException("Provider request interrupted", exception);
            }
        }
        // this line is only reached if something failed
        throw new ProviderCallException("Provider request failed after retry");
    }
    // encodes a string so it can be placed inside the url segment
    public static String pathSegment(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }
    // this is a simple data carrier that holds the api response
    public record ApiResponse(int status, JsonNode body, String rawBody) {}
}
