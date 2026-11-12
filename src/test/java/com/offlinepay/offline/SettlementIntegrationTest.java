package com.offlinepay.offline;

import com.offlinepay.model.User;
import com.offlinepay.model.UserStatus;
import com.offlinepay.offline.model.DeviceStatus;
import com.offlinepay.offline.model.FraudFlag;
import com.offlinepay.offline.model.SecurityEventType;
import com.offlinepay.offline.protocol.PayerCertificate;
import com.offlinepay.offline.protocol.PaymentToken;
import com.offlinepay.offline.repository.DeviceRepository;
import com.offlinepay.offline.service.OfflineWalletService;
import com.offlinepay.offline.service.SettlementResult;
import com.offlinepay.offline.service.SettlementService;
import com.offlinepay.offline.service.BankKeyService;
import com.offlinepay.repository.UserRepository;
import com.offlinepay.support.PhoneSimulator;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.math.BigDecimal;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * End-to-end tests of the mock bank: real database (H2 in memory), real services.
 * Every attack from the threat model is run against settlement.
 */
@SpringBootTest
@ActiveProfiles("test")
class SettlementIntegrationTest {

    @Autowired OfflineWalletService wallet;
    @Autowired SettlementService settlement;
    @Autowired BankKeyService bankKeys;
    @Autowired UserRepository users;
    @Autowired DeviceRepository devices;

    /** A user with ₦50,000, a registered phone and (optionally) a loaded offline wallet. */
    private record Person(User user, PhoneSimulator phone) {}

    private Person person(String name, String loadNaira) {
        User u = new User();
        u.setEmail(name.toLowerCase() + "-" + UUID.randomUUID() + "@test.ng");
        u.setDisplayName(name);
        u.setStatus(UserStatus.ACTIVE);
        u.setBalance(new BigDecimal("50000.00"));
        users.save(u);

        PhoneSimulator phone = new PhoneSimulator(name);
        var device = wallet.registerDevice(u.getId(), phone.publicKeyX509(), name + "'s phone");
        phone.setDeviceId(device.getId());
        if (loadNaira != null) {
            PayerCertificate cert = wallet.load(u.getId(), new BigDecimal(loadNaira)).certificate();
            phone.setCertificate(cert);
        }
        return new Person(u, phone);
    }

    private BigDecimal balance(Person p) {
        return users.findById(p.user().getId()).orElseThrow().getBalance();
    }

    private long reserveKobo(Person p) {
        return devices.findById(p.phone().deviceId()).orElseThrow().getReservedKobo();
    }

    private static void assertNaira(String expected, BigDecimal actual) {
        assertEquals(0, new BigDecimal(expected).compareTo(actual), "expected ₦" + expected + " but was ₦" + actual);
    }

    @Test
    void loadingMovesMoneyAndIssuesABankSignedCertificate() {
        Person ada = person("Ada", "10000");
        assertNaira("40000", balance(ada));
        assertEquals(1_000_000, reserveKobo(ada));
        assertTrue(ada.phone().certificate().isSignedBy(bankKeys.publicKey()));
        assertEquals(1_000_000, ada.phone().certificate().limitKobo());
    }

    @Test
    void validOfflinePaymentSettlesOnceEvenWhenBothSidesSync() {
        Person ada = person("Ada", "10000");
        Person bayo = person("Bayo", null);

        PaymentToken token = ada.phone().pay(bayo.phone().requestPayment(300_000)); // ₦3,000

        SettlementResult first = settlement.settle(token.toBase64Url(), bayo.user().getId());
        assertEquals(SettlementResult.Status.SETTLED, first.status());
        assertEquals(FraudFlag.NONE, first.fraudFlag());

        SettlementResult second = settlement.settle(token.toBase64Url(), ada.user().getId());
        assertEquals(SettlementResult.Status.ALREADY_SETTLED, second.status());

        assertNaira("40000", balance(ada));      // main balance untouched by the offline payment
        assertEquals(700_000, reserveKobo(ada));   // ₦7,000 left in the offline wallet
        assertNaira("53000", balance(bayo));      // received exactly once
    }

    @Test
    void tamperedTokenIsRejectedAndNoMoneyMoves() {
        Person ada = person("Ada", "10000");
        Person bayo = person("Bayo", null);
        PaymentToken t = ada.phone().pay(bayo.phone().requestPayment(100_000));
        PaymentToken edited = new PaymentToken(t.payerDeviceId(), t.receiverDeviceId(), 900_000, t.counter(),
                t.timestamp(), t.nonce(), t.certificate(), t.payerSignature());

        SettlementResult r = settlement.settle(edited.toBase64Url(), bayo.user().getId());
        assertEquals(SettlementResult.Status.REJECTED, r.status());
        assertEquals(SecurityEventType.TAMPERED_TOKEN, r.rejectionReason());
        assertNaira("50000", balance(bayo));
        assertEquals(1_000_000, reserveKobo(ada));
    }

    @Test
    void forgedCertificateIsRejected() {
        Person mallory = person("Mallory", null);
        Person bayo = person("Bayo", null);
        var fakeBank = com.offlinepay.offline.crypto.EcKeys.generateKeyPair();
        mallory.phone().setCertificate(PayerCertificate.issue(1, mallory.phone().deviceId(),
                mallory.phone().publicKeyRaw(), 2_000_000, System.currentTimeMillis() / 1000,
                System.currentTimeMillis() / 1000 + 86400, "Mallory", fakeBank.getPrivate()));

        PaymentToken t = mallory.phone().pay(bayo.phone().requestPayment(1_000_000));
        SettlementResult r = settlement.settle(t.toBase64Url(), bayo.user().getId());
        assertEquals(SecurityEventType.FORGED_CERTIFICATE, r.rejectionReason());
        assertNaira("50000", balance(bayo));
    }

    @Test
    void garbageTokenIsRejectedAsMalformed() {
        Person bayo = person("Bayo", null);
        SettlementResult r = settlement.settle("hello-this-is-not-a-token", bayo.user().getId());
        assertEquals(SecurityEventType.MALFORMED_TOKEN, r.rejectionReason());
    }

    @Test
    void strangerCannotSubmitSomeoneElsesPayment() {
        Person ada = person("Ada", "10000");
        Person bayo = person("Bayo", null);
        Person chidi = person("Chidi", null);
        PaymentToken t = ada.phone().pay(bayo.phone().requestPayment(100_000));

        SettlementResult r = settlement.settle(t.toBase64Url(), chidi.user().getId());
        assertEquals(SecurityEventType.NOT_A_PARTY, r.rejectionReason());
        assertNaira("50000", balance(chidi));
    }

    @Test
    void doubleSpendIsDetectedReceiverIsStillPaidAndPayerIsFrozen() {
        Person ada = person("Ada", "10000");
        Person bayo = person("Bayo", null);
        Person chidi = person("Chidi", null);

        // Ada's hacked app reuses counter 0 for two different people while offline
        PaymentToken toBayo = ada.phone().payWithCounter(bayo.phone().requestPayment(600_000), 0);
        PaymentToken toChidi = ada.phone().payWithCounter(chidi.phone().requestPayment(600_000), 0);

        assertEquals(FraudFlag.NONE, settlement.settle(toBayo.toBase64Url(), bayo.user().getId()).fraudFlag());
        SettlementResult second = settlement.settle(toChidi.toBase64Url(), chidi.user().getId());

        assertEquals(SettlementResult.Status.SETTLED, second.status());
        assertEquals(FraudFlag.DOUBLE_SPEND, second.fraudFlag());
        assertNaira("56000", balance(bayo));
        assertNaira("56000", balance(chidi));       // bank guarantee: honest receiver is paid
        assertNaira("38000", balance(ada));         // ₦2,000 shortfall recovered from Ada's main balance
        assertEquals(0, reserveKobo(ada));
        assertEquals(DeviceStatus.FROZEN, devices.findById(ada.phone().deviceId()).orElseThrow().getStatus());

        // a frozen device cannot load more money or get a new certificate
        assertThrows(IllegalStateException.class, () -> wallet.load(ada.user().getId(), new BigDecimal("1000")));
    }

    @Test
    void overspendIsDetectedAndRecovered() {
        Person ada = person("Ada", "5000");
        Person bayo = person("Bayo", null);
        Person chidi = person("Chidi", null);

        PaymentToken a = ada.phone().pay(bayo.phone().requestPayment(400_000));  // ₦4,000, counter 0
        PaymentToken b = ada.phone().pay(chidi.phone().requestPayment(400_000)); // ₦4,000, counter 1

        assertEquals(FraudFlag.NONE, settlement.settle(a.toBase64Url(), bayo.user().getId()).fraudFlag());
        assertEquals(FraudFlag.OVERSPEND, settlement.settle(b.toBase64Url(), chidi.user().getId()).fraudFlag());

        assertNaira("54000", balance(chidi));
        assertNaira("42000", balance(ada));         // 50,000 - 5,000 loaded - 3,000 recovered
        assertEquals(DeviceStatus.FROZEN, devices.findById(ada.phone().deviceId()).orElseThrow().getStatus());
    }

    @Test
    void walletLimitIsEnforced() {
        Person ada = person("Ada", "15000");
        assertThrows(IllegalStateException.class, () -> wallet.load(ada.user().getId(), new BigDecimal("6000")));
        assertEquals(1_500_000, reserveKobo(ada));
    }

    @Test
    void unloadReturnsUnspentMoney() {
        Person ada = person("Ada", "10000");
        wallet.unload(ada.user().getId(), new BigDecimal("4000"));
        assertNaira("44000", balance(ada));
        assertEquals(600_000, reserveKobo(ada));
    }

    @Test
    void newPhoneCannotBeRegisteredWhileMoneyIsStillOnTheOldOne() {
        Person ada = person("Ada", "10000");
        PhoneSimulator newPhone = new PhoneSimulator("Ada");
        assertThrows(IllegalStateException.class,
                () -> wallet.registerDevice(ada.user().getId(), newPhone.publicKeyX509(), "new phone"));
    }
}
