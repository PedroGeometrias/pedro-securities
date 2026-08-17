package com.pedroharo.threatlens.api;

import com.pedroharo.threatlens.nativecore.NativeCoreException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.multipart.MaxUploadSizeExceededException;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

// this file takes ll the possible execeptions and converts them into readable HTTP error responses, using the tag RestControllerAdvice,
// we don't need to spam try cathes everywhere througth out the program, another way that java simplifies boilerplate code
@RestControllerAdvice
public class ApiExceptionHandler {
	// logger is the basic logger construct, them we apply api exceptionhandler to define it
    private static final Logger log = LoggerFactory.getLogger(ApiExceptionHandler.class);

    // this method handles two different exceptions, the illegal arguments exceptions gappens when indicators are invalid, see
    // domain/indicatorType.java for the exact indicators that we use in this project, Method argument not valid is when the argument
    // is blank
    @ExceptionHandler({IllegalArgumentException.class, MethodArgumentNotValidException.class})
    public ResponseEntity<Map<String, Object>> badRequest(Exception exception) {
        String message = exception.getMessage();
        if (exception instanceof MethodArgumentNotValidException validation) {
            FieldError error = validation.getBindingResult().getFieldError();
            message = error == null ? "Request validation failed." : error.getDefaultMessage();
        }
        
        return error(HttpStatus.BAD_REQUEST, message);
    }

    // this happens when spring is processing a multipart updload, 
    @ExceptionHandler(MaxUploadSizeExceededException.class)
    public ResponseEntity<Map<String, Object>> tooLarge(MaxUploadSizeExceededException exception) {
    	
        return error(HttpStatus.PAYLOAD_TOO_LARGE, "File exceeds the 100 MB local-hashing limit.");
    }

    // happens when we don't find the value for a certain id
    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<Map<String, Object>> notFound(ResourceNotFoundException exception){
    	
        return error(HttpStatus.NOT_FOUND, exception.getMessage());
    }

    // external dependecy failed, in our case it could be database, c code, or something else
    @ExceptionHandler(NativeCoreException.class)
    public ResponseEntity<Map<String, Object>> nativeFailure(NativeCoreException exception) {
    	
        return error(HttpStatus.SERVICE_UNAVAILABLE, exception.getMessage());
    }

    // fallback error, something more misterious happened
    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> unexpected(Exception exception) {
        log.error("Unhandled API error", exception);
        return error(HttpStatus.INTERNAL_SERVER_ERROR,
                "The investigation could not be completed. Check the application logs for details.");
    }

    // this guy is the response body creator, it will place some important metadata on the execeptions, so it's easier to identify the problem
    private ResponseEntity<Map<String, Object>> error(HttpStatus status, String message) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("timestamp", Instant.now());
        body.put("status", status.value());
        body.put("error", status.getReasonPhrase());
        body.put("message", message == null ? status.getReasonPhrase() : message);
        return ResponseEntity.status(status).body(body);
    }
}
