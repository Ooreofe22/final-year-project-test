package com.offlinepay.offline.protocol;

/** Thrown when bytes from a QR code cannot be parsed into a valid message. */
public class ProtocolException extends RuntimeException {
    public ProtocolException(String message) {
        super(message);
    }
}
