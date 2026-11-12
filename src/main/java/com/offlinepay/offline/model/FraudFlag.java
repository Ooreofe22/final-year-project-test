package com.offlinepay.offline.model;

public enum FraudFlag {
    NONE,
    /** Two different payments signed with the same counter - the same money spent twice. */
    DOUBLE_SPEND,
    /** Payer spent more offline than the bank had reserved for them. */
    OVERSPEND
}
