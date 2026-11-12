package com.offlinepay.offline.repository;

import com.offlinepay.offline.model.SecurityEvent;
import com.offlinepay.offline.model.SecurityEventType;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface SecurityEventRepository extends JpaRepository<SecurityEvent, Long> {
    List<SecurityEvent> findAllByOrderByCreatedAtDesc();
    long countByType(SecurityEventType type);
}
