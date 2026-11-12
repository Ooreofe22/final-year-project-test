package com.offlinepay.repository;

import com.offlinepay.model.OtpCode;
import com.offlinepay.model.OtpPurpose;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface OtpCodeRepository extends JpaRepository<OtpCode, String> {
    Optional<OtpCode> findTopByEmailAndPurposeOrderByCreatedAtDesc(String email, OtpPurpose purpose);
    Optional<OtpCode> findTopByEmailAndPurposeAndConsumedFalseOrderByCreatedAtDesc(String email, OtpPurpose purpose);
}
