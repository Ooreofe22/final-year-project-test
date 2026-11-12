package com.offlinepay.offline.repository;

import com.offlinepay.offline.model.BankKey;
import org.springframework.data.jpa.repository.JpaRepository;

public interface BankKeyRepository extends JpaRepository<BankKey, String> {
}
