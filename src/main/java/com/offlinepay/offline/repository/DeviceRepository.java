package com.offlinepay.offline.repository;

import com.offlinepay.model.User;
import com.offlinepay.offline.model.Device;
import com.offlinepay.offline.model.DeviceStatus;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface DeviceRepository extends JpaRepository<Device, Long> {

    Optional<Device> findFirstByUserAndStatusInOrderByCreatedAtDesc(User user, List<DeviceStatus> statuses);

    List<Device> findByStatusOrderByUpdatedAtDesc(DeviceStatus status);

    List<Device> findAllByOrderByCreatedAtDesc();

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT d FROM Device d WHERE d.id = :id")
    Optional<Device> findByIdForUpdate(@Param("id") Long id);

    /** Locks the user's current device in the same query that reads it, so values are never stale. */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT d FROM Device d WHERE d.user = :user AND d.status IN :statuses ORDER BY d.createdAt DESC")
    List<Device> findCurrentForUpdate(@Param("user") User user, @Param("statuses") List<DeviceStatus> statuses);

    /** Who owns a device and its registered key - read without loading (or caching) the entity. */
    @Query("SELECT d.user.id AS userId, d.publicKey AS publicKey FROM Device d WHERE d.id = :id")
    Optional<DeviceOwner> findOwner(@Param("id") Long id);

    interface DeviceOwner {
        String getUserId();
        byte[] getPublicKey();
    }
}
