package com.offlinepay.offline.model;

/** Why a submitted token was rejected or flagged. Used for the evaluation chapter's attack statistics. */
public enum SecurityEventType {
    MALFORMED_TOKEN,
    FORGED_CERTIFICATE,
    CERTIFICATE_DEVICE_MISMATCH,
    TAMPERED_TOKEN,
    UNKNOWN_DEVICE,
    KEY_MISMATCH,
    CERTIFICATE_EXPIRED,
    OVER_CERTIFICATE_LIMIT,
    NOT_A_PARTY,
    DOUBLE_SPEND_DETECTED,
    OVERSPEND_DETECTED
}
