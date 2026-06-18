/*
 * Copyright 2026 Futit Services S.L.
 *
 * Licensed under the Etendo License Version 1.0.
 * You may not use this file except in compliance with the License.
 * You may find a copy of the License at:
 * https://github.com/etendosoftware/etendo_core/blob/main/legal/Etendo_license.txt
 */
package com.etendoerp.encryptedattachments;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mockStatic;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Properties;
import java.util.Random;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.openbravo.base.exception.OBException;
import org.openbravo.base.session.OBPropertiesProvider;
import org.openbravo.erpCommon.utility.OBMessageUtils;

import com.etendoerp.encryptedattachments.AttachmentCryptoService.ClientDek;

/**
 * Pure unit tests for {@link AttachmentCryptoService} — the cryptographic engine behind
 * the encrypted attachment method.
 *
 * <p>This is a JUnit 5 + Mockito test: it does NOT boot the DAL nor touch the database.
 * The master key is fed by setting a throwaway {@link java.util.Properties} on the real
 * {@link OBPropertiesProvider} singleton (restored after each test), and the static
 * {@link OBMessageUtils#messageBD} is stubbed with {@code mockStatic} so error paths can
 * build their {@code OBException} without a running message cache. This keeps the suite
 * fast and runnable anywhere (no server/DB required).
 *
 * <p>It lives in the same package as the service on purpose, to exercise the
 * package-private key-wrapping helpers ({@code loadKek}, {@code wrapDek}, {@code unwrapDek}).
 */
class AttachmentCryptoServiceTest {

  /** 32 zero bytes = a valid (deterministic) 256-bit AES test key. */
  private static final String TEST_KEK_B64 = Base64.getEncoder().encodeToString(new byte[32]);

  private static final byte[] SAMPLE = "TOP-SECRET-MARKER: certificate contents 1234567890"
      .getBytes(StandardCharsets.UTF_8);

  private MockedStatic<OBMessageUtils> messagesMock;
  private Properties props;
  private Properties originalProps;
  private AttachmentCryptoService service;

  @BeforeEach
  void setUp() {
    // Feed the master key (KEK) via a throwaway Properties on the real singleton,
    // preserving any existing properties so we can restore them afterwards.
    OBPropertiesProvider provider = OBPropertiesProvider.getInstance();
    try {
      originalProps = provider.getOpenbravoProperties();
    } catch (RuntimeException | LinkageError notInitialised) {
      // Running outside a full server - only the master key set below is needed.
      originalProps = null;
    }
    props = new Properties();
    if (originalProps != null) {
      props.putAll(originalProps);
    }
    props.setProperty(AttachmentCryptoService.MASTER_KEY_PROPERTY, TEST_KEK_B64);
    provider.setProperties(props);

    // messageBD just echoes the message key, so error paths can build their OBException.
    messagesMock = mockStatic(OBMessageUtils.class);
    messagesMock.when(() -> OBMessageUtils.messageBD(anyString()))
        .thenAnswer(invocation -> invocation.getArgument(0));

    service = new AttachmentCryptoService();
  }

  @AfterEach
  void tearDown() {
    if (messagesMock != null) {
      messagesMock.close();
    }
    if (originalProps != null) {
      OBPropertiesProvider.getInstance().setProperties(originalProps);
    }
  }

  // ------------------------------------------------------------------ //
  //  File encryption / decryption
  // ------------------------------------------------------------------ //

  @Test
  @DisplayName("A file encrypted and decrypted with the same key is recovered intact")
  void encryptDecryptRoundTrip() throws Exception {
    SecretKey dek = newAesKey();
    byte[] encrypted = service.encrypt(SAMPLE, dek, 1);
    byte[] decrypted = service.decrypt(encrypted, dek);
    assertArrayEquals(SAMPLE, decrypted, "round-trip must recover the original bytes");
  }

  @Test
  @DisplayName("On-disk output starts with the ETEC magic and never contains the plaintext")
  void encryptedOutputHasMagicHeaderAndHidesPlaintext() throws Exception {
    SecretKey dek = newAesKey();
    byte[] encrypted = service.encrypt(SAMPLE, dek, 1);

    assertEquals("ETEC", new String(encrypted, 0, 4, StandardCharsets.US_ASCII),
        "file must start with the ETEC magic");
    assertTrue(encrypted.length >= AttachmentCryptoService.HEADER_SIZE + SAMPLE.length,
        "output must be header + ciphertext + GCM tag");
    assertFalse(containsSubsequence(encrypted, SAMPLE),
        "plaintext must not appear in the encrypted output");
  }

  @Test
  @DisplayName("CORE: a file encrypted by one client cannot be decrypted by another client")
  void crossClientDecryptionFails() throws Exception {
    SecretKey dekClientA = newAesKey();
    SecretKey dekClientB = newAesKey();

    byte[] encryptedByA = service.encrypt(SAMPLE, dekClientA, 1);

    // GCM auth-tag mismatch -> access denied. This is the tenant-isolation guarantee.
    assertThrows(OBException.class, () -> service.decrypt(encryptedByA, dekClientB),
        "decrypting client A's file with client B's key must fail");
  }

  @Test
  @DisplayName("Tampering with the ciphertext/tag is detected (GCM integrity)")
  void tamperedCiphertextIsRejected() throws Exception {
    SecretKey dek = newAesKey();
    byte[] encrypted = service.encrypt(SAMPLE, dek, 1);
    encrypted[encrypted.length - 1] ^= 0x01; // flip one bit of the GCM tag

    assertThrows(OBException.class, () -> service.decrypt(encrypted, dek),
        "tampered ciphertext must not decrypt");
  }

  @Test
  @DisplayName("Input without the ETEC header is rejected")
  void nonEncryptedInputIsRejected() throws Exception {
    SecretKey dek = newAesKey();
    byte[] notOurs = "‰PNG....just a normal file".getBytes(StandardCharsets.UTF_8);
    assertThrows(OBException.class, () -> service.decrypt(notOurs, dek),
        "input without the ETEC header must be rejected");
  }

  // ------------------------------------------------------------------ //
  //  Edge cases
  // ------------------------------------------------------------------ //

  @Test
  void emptyFileRoundTrip() throws Exception {
    SecretKey dek = newAesKey();
    byte[] empty = new byte[0];
    byte[] encrypted = service.encrypt(empty, dek, 1);

    assertEquals("ETEC", new String(encrypted, 0, 4, StandardCharsets.US_ASCII));
    assertArrayEquals(empty, service.decrypt(encrypted, dek));
  }

  @Test
  void largeFileRoundTrip() throws Exception {
    SecretKey dek = newAesKey();
    byte[] large = new byte[2 * 1024 * 1024]; // 2 MB
    new Random(42).nextBytes(large);          // fixed seed -> reproducible

    byte[] encrypted = service.encrypt(large, dek, 1);
    assertArrayEquals(large, service.decrypt(encrypted, dek));
  }

  // ------------------------------------------------------------------ //
  //  DEK wrapping (envelope encryption) and dump resistance
  // ------------------------------------------------------------------ //

  @Test
  @DisplayName("Wrapping then unwrapping recovers the DEK and never exposes the raw key")
  void wrapUnwrapRoundTripAndDumpResistance() throws Exception {
    SecretKey dek = newAesKey();

    String wrapped = service.wrapDek(dek, 1);
    byte[] wrappedBytes = Base64.getDecoder().decode(wrapped);

    assertNotEquals(Base64.getEncoder().encodeToString(dek.getEncoded()), wrapped,
        "wrapped DEK must differ from the raw key");
    assertFalse(containsSubsequence(wrappedBytes, dek.getEncoded()),
        "raw key bytes must not appear in the wrapped blob");

    SecretKey unwrapped = service.unwrapDek(wrapped, 1);
    assertArrayEquals(dek.getEncoded(), unwrapped.getEncoded(),
        "unwrap must recover the original DEK");
  }

  @Test
  @DisplayName("The key version is authenticated: unwrapping with the wrong version fails")
  void unwrapWithWrongKeyVersionFails() throws Exception {
    SecretKey dek = newAesKey();
    String wrapped = service.wrapDek(dek, 1);
    assertThrows(OBException.class, () -> service.unwrapDek(wrapped, 2),
        "unwrapping with a mismatched key version must fail");
  }

  @Test
  @DisplayName("A wrapped DEK is useless without the correct master key (dump resistance)")
  void wrappedDekUnreadableWithoutCorrectKek() throws Exception {
    SecretKey dek = newAesKey();
    String wrapped = service.wrapDek(dek, 1);

    // Simulate an attacker who has the DB dump but a different/guessed master key.
    byte[] otherKek = new byte[32];
    otherKek[0] = 0x7F;
    props.setProperty(AttachmentCryptoService.MASTER_KEY_PROPERTY,
        Base64.getEncoder().encodeToString(otherKek));
    // setProperties copies the Properties object, so we must re-apply after modifying.
    OBPropertiesProvider.getInstance().setProperties(props);

    assertThrows(OBException.class, () -> service.unwrapDek(wrapped, 1),
        "wrapped DEK must not unwrap with the wrong master key");
  }

  @Test
  @DisplayName("A missing master key fails loudly (no silent fallback)")
  void missingMasterKeyThrows() {
    props.remove(AttachmentCryptoService.MASTER_KEY_PROPERTY);
    // setProperties copies the Properties object, so we must re-apply after modifying.
    OBPropertiesProvider.getInstance().setProperties(props);
    assertThrows(OBException.class, () -> service.loadKek(),
        "a missing master key must raise an OBException");
  }

  // ------------------------------------------------------------------ //
  //  Service / DEK behaviour
  // ------------------------------------------------------------------ //

  @Test
  @DisplayName("A wrapped-then-unwrapped DEK still encrypts and decrypts files end to end")
  void wrappedDekStillDecryptsFiles() throws Exception {
    SecretKey dek = newAesKey();
    String wrapped = service.wrapDek(dek, 1);
    ClientDek restored = new ClientDek(service.unwrapDek(wrapped, 1), 1);

    byte[] encrypted = service.encrypt(SAMPLE, restored.getKey(), restored.getKeyVersion());
    assertArrayEquals(SAMPLE, service.decrypt(encrypted, restored.getKey()));
  }

  @Test
  @DisplayName("Downloads are flagged as temporary so the decrypted copy gets deleted")
  void downloadProducesTempFiles() {
    assertTrue(new EncryptedAttachImplementation().isTempFile(),
        "decrypted downloads must be flagged as temporary");
  }

  @Test
  @DisplayName("An invalid base64 master key fails loudly")
  void invalidMasterKeyThrows() {
    props.setProperty(AttachmentCryptoService.MASTER_KEY_PROPERTY, "%%%not-base64%%%");
    OBPropertiesProvider.getInstance().setProperties(props);

    assertThrows(OBException.class, () -> service.loadKek(),
        "an invalid master key must raise an OBException");
  }

  @Test
  @DisplayName("A truncated encrypted payload is rejected before attempting GCM decryption")
  void truncatedHeaderIsRejected() throws Exception {
    SecretKey dek = newAesKey();
    byte[] tooShort = new byte[AttachmentCryptoService.HEADER_SIZE - 1];

    assertThrows(OBException.class, () -> service.decrypt(tooShort, dek),
        "payloads shorter than the header must be rejected");
  }

  // ------------------------------------------------------------------ //
  //  Helpers
  // ------------------------------------------------------------------ //

  private static SecretKey newAesKey() throws NoSuchAlgorithmException {
    KeyGenerator kg = KeyGenerator.getInstance("AES");
    kg.init(256);
    return kg.generateKey();
  }

  /** Naive check: does {@code haystack} contain {@code needle} as a contiguous run? */
  private static boolean containsSubsequence(byte[] haystack, byte[] needle) {
    if (needle.length == 0 || needle.length > haystack.length) {
      return false;
    }
    for (int i = 0; i <= haystack.length - needle.length; i++) {
      if (matchesAt(haystack, needle, i)) {
        return true;
      }
    }
    return false;
  }

  private static boolean matchesAt(byte[] haystack, byte[] needle, int offset) {
    for (int j = 0; j < needle.length; j++) {
      if (haystack[offset + j] != needle[j]) {
        return false;
      }
    }
    return true;
  }
}
