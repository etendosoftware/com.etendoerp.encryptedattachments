/*
 * Copyright 2026 Futit Services S.L.
 *
 * Licensed under the Etendo License Version 1.0.
 * You may not use this file except in compliance with the License.
 * You may find a copy of the License at:
 * https://github.com/etendosoftware/etendo_core/blob/main/legal/Etendo_license.txt
 */
package com.etendoerp.encryptedattachments;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.enterprise.context.ApplicationScoped;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.hibernate.criterion.Restrictions;
import org.openbravo.base.exception.OBException;
import org.openbravo.base.provider.OBProvider;
import org.openbravo.base.session.OBPropertiesProvider;
import org.openbravo.dal.core.OBContext;
import org.openbravo.dal.service.OBCriteria;
import org.openbravo.dal.service.OBDal;
import org.openbravo.erpCommon.utility.OBMessageUtils;
import org.openbravo.model.ad.system.Client;
import org.openbravo.model.common.enterprise.Organization;

import com.etendoerp.encryptedattachments.data.ClientKey;


/**
 * Provides AES-256-GCM envelope encryption for attachment files.
 *
 * <p>Envelope encryption model:
 * <ul>
 *   <li>KEK (master key): base64 in Openbravo.properties under
 *       {@code attachment.encryption.masterkey}. Lives outside the DB.</li>
 *   <li>DEK (per-client data key): random 256-bit key, stored wrapped
 *       (AES-GCM encrypted with the KEK) in {@code ETENC_CLIENT_KEY}.</li>
 * </ul>
 *
 * <p>On-disk file format:
 * <pre>
 *   [magic(4)] [version(1)] [keyVersion(4,BE)] [iv(12)] [ciphertext+tag]
 * </pre>
 */
@ApplicationScoped
public class AttachmentCryptoService {

  private static final Logger log = LogManager.getLogger();

  static final String MASTER_KEY_PROPERTY = "attachment.encryption.masterkey";

  private static final String AES_GCM = "AES/GCM/NoPadding";
  private static final int    GCM_IV_LEN  = 12;
  private static final int    GCM_TAG_LEN = 128; // bits

  // File header: "ETEC" magic (4 bytes)
  private static final byte[] MAGIC = { 'E', 'T', 'E', 'C' };
  private static final byte   FORMAT_VERSION = 0x01;

  // Header total size: magic(4) + version(1) + keyVersion(4) + iv(12) = 21
  static final int HEADER_SIZE = 21;

  private final SecureRandom random = new SecureRandom();

  /** Immutable holder for a client's DEK together with its key version. */
  public static final class ClientDek {
    private final SecretKey key;
    private final int keyVersion;

    ClientDek(SecretKey key, int keyVersion) {
      this.key = key;
      this.keyVersion = keyVersion;
    }

    public SecretKey getKey() {
      return key;
    }

    public int getKeyVersion() {
      return keyVersion;
    }
  }

  // ------------------------------------------------------------------ //
  //  KEK loading
  // ------------------------------------------------------------------ //

  /** Loads the KEK from Openbravo.properties. Throws OBException if missing or invalid. */
  SecretKey loadKek() {
    String b64 = OBPropertiesProvider.getInstance()
        .getOpenbravoProperties()
        .getProperty(MASTER_KEY_PROPERTY);
    if (b64 == null || b64.isEmpty()) {
      throw new OBException(OBMessageUtils.messageBD("ETENC_MissingMasterKey"));
    }
    try {
      byte[] raw = Base64.getDecoder().decode(b64.trim());
      return new SecretKeySpec(raw, "AES");
    } catch (IllegalArgumentException e) {
      throw new OBException(OBMessageUtils.messageBD("ETENC_MissingMasterKey"), e);
    }
  }

  // ------------------------------------------------------------------ //
  //  DEK management
  // ------------------------------------------------------------------ //

  /**
   * Returns the DEK for {@code client}, creating and persisting it on demand.
   * Runs in admin mode to bypass org/client filters on ETENC_CLIENT_KEY.
   *
   * @param client the Etendo client whose DEK to fetch or create
   * @return the client's active DEK together with its version number
   */
  public ClientDek getOrCreateDek(Client client) {
    try {
      OBContext.setAdminMode(true);
      ClientKey keyRecord = findClientKeyRecord(client.getId());
      if (keyRecord != null) {
        int keyVersion = (int) (long) keyRecord.getKeyVersion();
        log.debug("Using existing DEK for client {} (keyVersion {})", client.getId(), keyVersion);
        return new ClientDek(unwrapDek(keyRecord.getWrappedDEK(), keyVersion), keyVersion);
      }
      return createAndStoreDek(client);
    } finally {
      OBContext.restorePreviousMode();
    }
  }

  private ClientKey findClientKeyRecord(String clientId) {
    OBCriteria<ClientKey> crit = OBDal.getInstance().createCriteria(ClientKey.class);
    crit.add(Restrictions.eq(ClientKey.PROPERTY_CLIENT + ".id", clientId));
    crit.setFilterOnReadableOrganization(false);
    crit.setMaxResults(1);
    return (ClientKey) crit.uniqueResult();
  }

  private ClientDek createAndStoreDek(Client client) {
    try {
      KeyGenerator kg = KeyGenerator.getInstance("AES");
      kg.init(256, random);
      SecretKey dek = kg.generateKey();

      String wrapped = wrapDek(dek, 1);

      ClientKey keyRecord = OBProvider.getInstance().get(ClientKey.class);
      keyRecord.setClient(client);
      keyRecord.setOrganization(OBDal.getInstance().get(Organization.class, "0"));
      keyRecord.setActive(true);
      keyRecord.setWrappedDEK(wrapped);
      keyRecord.setKeyVersion(1L);
      keyRecord.setKEKVersion(1L);
      OBDal.getInstance().save(keyRecord);
      OBDal.getInstance().flush();

      log.info("Generated new DEK for client {}", client.getId());
      return new ClientDek(dek, 1);
    } catch (Exception e) {
      throw new OBException("Failed to generate DEK for client " + client.getId(), e);
    }
  }

  /**
   * Wraps {@code dek} with the KEK using AES-GCM.
   * Stored format: base64( iv(12) + ciphertext+tag ).
   */
  String wrapDek(SecretKey dek, int keyVersion) {
    SecretKey kek = loadKek();
    byte[] iv = new byte[GCM_IV_LEN];
    random.nextBytes(iv);
    try {
      Cipher cipher = Cipher.getInstance(AES_GCM);
      cipher.init(Cipher.ENCRYPT_MODE, kek, new GCMParameterSpec(GCM_TAG_LEN, iv));
      // Include keyVersion as AAD so it's authenticated
      cipher.updateAAD(ByteBuffer.allocate(4).putInt(keyVersion).array());
      byte[] ct = cipher.doFinal(dek.getEncoded());

      byte[] wrapped = new byte[GCM_IV_LEN + ct.length];
      System.arraycopy(iv, 0, wrapped, 0, GCM_IV_LEN);
      System.arraycopy(ct, 0, wrapped, GCM_IV_LEN, ct.length);
      return Base64.getEncoder().encodeToString(wrapped);
    } catch (Exception e) {
      throw new OBException("Failed to wrap DEK", e);
    }
  }

  /** Unwraps the DEK stored in the DB. Throws OBException on any failure. */
  SecretKey unwrapDek(String wrappedB64, int keyVersion) {
    SecretKey kek = loadKek();
    try {
      byte[] wrapped = Base64.getDecoder().decode(wrappedB64);
      byte[] iv = Arrays.copyOfRange(wrapped, 0, GCM_IV_LEN);
      byte[] ct = Arrays.copyOfRange(wrapped, GCM_IV_LEN, wrapped.length);

      Cipher cipher = Cipher.getInstance(AES_GCM);
      cipher.init(Cipher.DECRYPT_MODE, kek, new GCMParameterSpec(GCM_TAG_LEN, iv));
      cipher.updateAAD(ByteBuffer.allocate(4).putInt(keyVersion).array());
      byte[] raw = cipher.doFinal(ct);
      return new SecretKeySpec(raw, "AES");
    } catch (Exception e) {
      log.error("DEK unwrap failed", e);
      throw new OBException(OBMessageUtils.messageBD("ETENC_DekUnwrapFailure"), e);
    }
  }

  // ------------------------------------------------------------------ //
  //  File encrypt / decrypt
  // ------------------------------------------------------------------ //

  /**
   * Encrypts {@code plaintext} with {@code dek} using AES-256-GCM.
   *
   * @param plaintext  raw bytes to encrypt
   * @param dek        the AES-256 data encryption key
   * @param keyVersion the DEK's key_version — written into the file header
   * @return byte array with header + ciphertext+tag
   */
  public byte[] encrypt(byte[] plaintext, SecretKey dek, int keyVersion) {
    byte[] iv = new byte[GCM_IV_LEN];
    random.nextBytes(iv);
    try {
      Cipher cipher = Cipher.getInstance(AES_GCM);
      cipher.init(Cipher.ENCRYPT_MODE, dek, new GCMParameterSpec(GCM_TAG_LEN, iv));
      byte[] ct = cipher.doFinal(plaintext);

      // Header: magic(4) + version(1) + keyVersion(4,BE) + iv(12)
      ByteBuffer buf = ByteBuffer.allocate(HEADER_SIZE + ct.length);
      buf.put(MAGIC);
      buf.put(FORMAT_VERSION);
      buf.putInt(keyVersion);
      buf.put(iv);
      buf.put(ct);
      return buf.array();
    } catch (Exception e) {
      throw new OBException("Encryption failed", e);
    }
  }

  /**
   * Decrypts a file produced by {@link #encrypt}.
   * The DEK must correspond to the keyVersion stored in the header.
   * A GCM tag mismatch (e.g. wrong DEK from a different client) throws OBException.
   *
   * @param cipherFile encrypted byte array in the format written by {@link #encrypt}
   * @param dek        the AES-256 data encryption key for this client
   * @return the original plaintext bytes
   */
  public byte[] decrypt(byte[] cipherFile, SecretKey dek) {
    if (cipherFile.length < HEADER_SIZE) {
      throw new OBException("Encrypted file is too short to contain a valid header");
    }
    ByteBuffer buf = ByteBuffer.wrap(cipherFile);

    // Validate magic
    byte[] magic = new byte[4];
    buf.get(magic);
    if (!Arrays.equals(magic, MAGIC)) {
      throw new OBException("Not an encrypted attachment (invalid magic)");
    }

    buf.get(); // version (reserved for future format changes)
    buf.getInt(); // keyVersion (informational; DEK already selected by caller)

    byte[] iv = new byte[GCM_IV_LEN];
    buf.get(iv);

    byte[] ct = new byte[buf.remaining()];
    buf.get(ct);

    try {
      Cipher cipher = Cipher.getInstance(AES_GCM);
      cipher.init(Cipher.DECRYPT_MODE, dek, new GCMParameterSpec(GCM_TAG_LEN, iv));
      return cipher.doFinal(ct);
    } catch (Exception e) {
      throw new OBException(OBMessageUtils.messageBD("ETENC_CrossClientDecryptionFailed"), e);
    }
  }
}
