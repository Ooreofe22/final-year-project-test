package com.offlinepay.offline.service;

import com.offlinepay.offline.model.FraudFlag;
import com.offlinepay.offline.model.SecurityEventType;

import java.math.BigDecimal;

public record SettlementResult(
        String paymentId,
        Status status,
        SecurityEventType rejectionReason,
        FraudFlag fraudFlag,
        BigDecimal amount,
        String payerName,
        String receiverName,
        String message) {

    public enum Status {
        /** Newly settled into the ledger. */
        SETTLED,
        /** Already settled earlier (e.g. the other party synced it first) - nothing changed. */
        ALREADY_SETTLED,
        /** Failed a security check - no money moved. */
        REJECTED
    }

    static SettlementResult rejected(String paymentId, SecurityEventType reason, String message) {
        return new SettlementResult(paymentId, Status.REJECTED, reason, FraudFlag.NONE, null, null, null, message);
    }
}
