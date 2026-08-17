package com.pedroharo.threatlens.api;

// signals that something wasn't found
public class ResourceNotFoundException extends RuntimeException {
    public ResourceNotFoundException(String message) {
        super(message);
    }
}
