package com.offlinepay.offline.model;

public enum DeviceStatus {
    /** Normal - can load the wallet and receive new certificates. */
    ACTIVE,
    /** Fraud detected (double-spend or overspend). No new loads or certificates until an admin reviews it. */
    FROZEN,
    /** Replaced by a newer device registration for the same user. */
    REVOKED
}
