package com.offlinepay.offline.service;

import java.math.BigDecimal;
import java.math.RoundingMode;

/** Naira (BigDecimal, as stored on User.balance) <-> kobo (long, as used in tokens). */
public final class Money {

    private static final BigDecimal HUNDRED = BigDecimal.valueOf(100);

    private Money() {}

    public static long toKobo(BigDecimal naira) {
        if (naira == null) throw new IllegalArgumentException("Amount is required");
        BigDecimal scaled = naira.setScale(2, RoundingMode.UNNECESSARY);
        return scaled.multiply(HUNDRED).longValueExact();
    }

    public static BigDecimal toNaira(long kobo) {
        return BigDecimal.valueOf(kobo).divide(HUNDRED).setScale(2, RoundingMode.UNNECESSARY);
    }
}
