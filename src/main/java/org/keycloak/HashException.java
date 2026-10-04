package org.keycloak;


public class HashException extends RuntimeException {

    public HashException(String message) {
        super(message);
    }

    public HashException(String message, Throwable cause) {
        super(message, cause);
    }
}
