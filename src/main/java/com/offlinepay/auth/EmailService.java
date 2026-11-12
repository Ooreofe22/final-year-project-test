package com.offlinepay.auth;

public interface EmailService {
    void sendOtp(String email, String code);
}
