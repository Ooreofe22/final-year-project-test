package com.offlinepay.offline.repository;

import com.offlinepay.offline.model.FraudFlag;
import com.offlinepay.offline.model.OfflinePayment;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface OfflinePaymentRepository extends JpaRepository<OfflinePayment, Long> {

    Optional<OfflinePayment> findByPaymentId(String paymentId);

    List<OfflinePayment> findByPayerDeviceIdAndCounter(long payerDeviceId, long counter);

    List<OfflinePayment> findByPayerUserIdOrReceiverUserIdOrderBySettledAtDesc(String payerUserId, String receiverUserId);

    List<OfflinePayment> findByFraudFlagNotOrderBySettledAtDesc(FraudFlag flag);

    List<OfflinePayment> findAllByOrderBySettledAtDesc();

    long countByFraudFlag(FraudFlag flag);

    @Query("SELECT COALESCE(SUM(p.amountKobo), 0) FROM OfflinePayment p")
    long totalVolumeKobo();
}
