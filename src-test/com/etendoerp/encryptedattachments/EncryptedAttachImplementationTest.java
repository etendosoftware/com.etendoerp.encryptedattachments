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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.File;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.Properties;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.MockedStatic;
import org.openbravo.base.exception.OBException;
import org.openbravo.base.session.OBPropertiesProvider;
import org.openbravo.dal.core.OBContext;
import org.openbravo.dal.service.OBCriteria;
import org.openbravo.dal.service.OBDal;
import org.openbravo.erpCommon.businessUtility.Preferences;
import org.openbravo.erpCommon.utility.OBMessageUtils;
import org.openbravo.model.ad.datamodel.Table;
import org.openbravo.model.ad.access.Role;
import org.openbravo.model.ad.access.User;
import org.openbravo.model.ad.system.Client;
import org.openbravo.model.ad.ui.Window;
import org.openbravo.model.ad.utility.Attachment;
import org.openbravo.model.common.enterprise.Organization;

class EncryptedAttachImplementationTest {

  private static final byte[] SAMPLE = "very secret attachment content"
      .getBytes(StandardCharsets.UTF_8);

  @TempDir
  Path tempDir;

  private final AttachmentCryptoService engine = new AttachmentCryptoService();

  private Properties originalProps;
  private MockedStatic<OBContext> obContextMock;
  private MockedStatic<OBDal> obDalMock;
  private MockedStatic<Preferences> preferencesMock;
  private MockedStatic<OBMessageUtils> messagesMock;

  private OBDal dal;
  private OBContext obContext;
  private AttachmentCryptoService cryptoService;
  private EncryptedAttachImplementation implementation;
  private Attachment attachment;
  private Table table;
  private Client client;
  private SecretKey dek;

  @BeforeEach
  void setUp() throws Exception {
    originalProps = OBPropertiesProvider.getInstance().getOpenbravoProperties();
    Properties props = new Properties();
    if (originalProps != null) {
      props.putAll(originalProps);
    }
    props.setProperty("attach.path", tempDir.toString());
    OBPropertiesProvider.getInstance().setProperties(props);

    dal = mock(OBDal.class);
    obContext = mock(OBContext.class);
    obDalMock = mockStatic(OBDal.class);
    obDalMock.when(OBDal::getInstance).thenReturn(dal);

    obContextMock = mockStatic(OBContext.class);
    obContextMock.when(OBContext::getOBContext).thenReturn(obContext);

    preferencesMock = mockStatic(Preferences.class);
    preferencesMock.when(() -> Preferences.getPreferenceValue(anyString(), anyBoolean(),
        nullable(Client.class), nullable(Organization.class), nullable(User.class),
        nullable(Role.class), nullable(Window.class))).thenReturn(Preferences.YES);

    messagesMock = mockStatic(OBMessageUtils.class);
    messagesMock.when(() -> OBMessageUtils.messageBD(anyString()))
        .thenAnswer(invocation -> invocation.getArgument(0));

    table = mock(Table.class);
    when(table.getId()).thenReturn("C0FFEE");

    attachment = mock(Attachment.class);
    when(attachment.getTable()).thenReturn(table);
    when(attachment.getRecord()).thenReturn("00112233445566778899AABBCCDDEEFF");
    when(attachment.getName()).thenReturn("certificate.p12");

    client = mock(Client.class);
    when(client.getId()).thenReturn("A1B2C3");
    when(obContext.getCurrentClient()).thenReturn(client);

    dek = newAesKey();
    cryptoService = mock(AttachmentCryptoService.class);
    when(cryptoService.getOrCreateDek(client))
        .thenReturn(new AttachmentCryptoService.ClientDek(dek, 7));
    when(cryptoService.encrypt(any(byte[].class), same(dek), eq(7)))
        .thenAnswer(invocation -> engine.encrypt(invocation.getArgument(0), dek, 7));
    when(cryptoService.decrypt(any(byte[].class), same(dek)))
        .thenAnswer(invocation -> engine.decrypt(invocation.getArgument(0), dek));

    implementation = new EncryptedAttachImplementation();
    injectCryptoService(implementation, cryptoService);
  }

  @AfterEach
  void tearDown() {
    if (messagesMock != null) {
      messagesMock.close();
    }
    if (preferencesMock != null) {
      preferencesMock.close();
    }
    if (obContextMock != null) {
      obContextMock.close();
    }
    if (obDalMock != null) {
      obDalMock.close();
    }
    if (originalProps != null) {
      OBPropertiesProvider.getInstance().setProperties(originalProps);
    }
  }

  @Test
  @DisplayName("uploadFile encrypts the source content before delegating to the core storage path")
  void uploadFileStoresEncryptedBytes() throws Exception {
    Path source = tempDir.resolve("certificate.p12");
    Files.write(source, SAMPLE);

    implementation.uploadFile(attachment, "binary", Collections.emptyMap(), source.toFile(), "TAB");

    Path stored = expectedStoredPath();
    assertTrue(Files.exists(stored), "the core storage file must exist");
    assertFalse(Files.exists(source), "the source temp file must be deleted by the core upload");

    byte[] encrypted = Files.readAllBytes(stored);
    assertNotEquals(new String(SAMPLE, StandardCharsets.UTF_8),
        new String(encrypted, StandardCharsets.ISO_8859_1));
    assertArrayEquals(SAMPLE, engine.decrypt(encrypted, dek));

    verify(attachment).setPath(null);
    verify(dal).save(attachment);
    verify(cryptoService).encrypt(SAMPLE, dek, 7);
  }

  @Test
  @DisplayName("uploadFile wraps I/O failures while reading the plaintext source")
  void uploadFileWrapsReadFailures() {
    File missing = tempDir.resolve("missing-source.bin").toFile();

    OBException exception = assertThrows(OBException.class,
        () -> implementation.uploadFile(attachment, "binary", Collections.emptyMap(), missing, "TAB"));

    assertTrue(exception.getMessage().contains("Failed to encrypt attachment certificate.p12"));
    verify(dal, never()).save(any());
  }

  @Test
  @DisplayName("downloadFile returns the core file untouched when it does not exist on disk")
  void downloadFileReturnsMissingCoreFile() {
    mockDownloadPathLookup(null);

    File downloaded = implementation.downloadFile(attachment);

    assertEquals(expectedStoredPath().toFile().getAbsolutePath(), downloaded.getAbsolutePath());
    assertFalse(downloaded.exists());
    verify(cryptoService, never()).getOrCreateDek(any());
    verify(cryptoService, never()).decrypt(any(byte[].class), any());
  }

  @Test
  @DisplayName("downloadFile decrypts the stored bytes into a temporary file")
  void downloadFileDecryptsIntoTempCopy() throws Exception {
    mockDownloadPathLookup(null);
    Files.createDirectories(expectedStoredPath().getParent());
    Files.write(expectedStoredPath(), engine.encrypt(SAMPLE, dek, 7));

    File downloaded = implementation.downloadFile(attachment);

    assertTrue(downloaded.exists());
    assertEquals("certificate.p12", downloaded.getName());
    assertNotEquals(expectedStoredPath().toFile().getAbsolutePath(), downloaded.getAbsolutePath());
    assertArrayEquals(SAMPLE, Files.readAllBytes(downloaded.toPath()));
    assertFalse(containsPlaintext(Files.readAllBytes(expectedStoredPath())));
  }

  @Test
  @DisplayName("downloadFile propagates the cross-client decrypt failure")
  void downloadFilePropagatesDecryptFailure() throws Exception {
    mockDownloadPathLookup(null);
    Files.createDirectories(expectedStoredPath().getParent());
    Files.write(expectedStoredPath(), engine.encrypt(SAMPLE, newAesKey(), 7));

    OBException exception = assertThrows(OBException.class,
        () -> implementation.downloadFile(attachment));

    assertEquals("ETENC_CrossClientDecryptionFailed", exception.getMessage());
  }

  @Test
  @DisplayName("downloadFile wraps I/O failures while reading the stored encrypted file")
  void downloadFileWrapsReadFailures() throws Exception {
    mockDownloadPathLookup(null);
    Files.createDirectories(expectedStoredPath());

    OBException exception = assertThrows(OBException.class,
        () -> implementation.downloadFile(attachment));

    assertTrue(exception.getMessage().contains("Failed to decrypt attachment certificate.p12"));
  }

  @Test
  void isTempFileReturnsTrue() {
    assertTrue(implementation.isTempFile());
  }

  private void injectCryptoService(EncryptedAttachImplementation target,
      AttachmentCryptoService service) throws Exception {
    Field field = EncryptedAttachImplementation.class.getDeclaredField("cryptoService");
    field.setAccessible(true);
    field.set(target, service);
  }

  @SuppressWarnings("unchecked")
  private void mockDownloadPathLookup(String storedPath) {
    when(dal.get(eq(Table.class), anyString())).thenReturn(table);
    OBCriteria<Attachment> criteria = mock(OBCriteria.class);
    when(dal.createCriteria(Attachment.class)).thenReturn(criteria);
    when(criteria.add(any())).thenReturn(criteria);
    when(criteria.setFilterOnReadableOrganization(false)).thenReturn(criteria);
    when(criteria.setMaxResults(anyInt())).thenReturn(criteria);

    Attachment storedAttachment = null;
    if (storedPath != null) {
      storedAttachment = mock(Attachment.class);
      when(storedAttachment.getPath()).thenReturn(storedPath);
    }
    when(criteria.uniqueResult()).thenReturn(storedAttachment);
  }

  private Path expectedStoredPath() {
    return tempDir.resolve("C0FFEE-00112233445566778899AABBCCDDEEFF")
        .resolve("certificate.p12");
  }

  private boolean containsPlaintext(byte[] encryptedBytes) {
    return new String(encryptedBytes, StandardCharsets.ISO_8859_1)
        .contains(new String(SAMPLE, StandardCharsets.UTF_8));
  }

  private SecretKey newAesKey() throws Exception {
    KeyGenerator kg = KeyGenerator.getInstance("AES");
    kg.init(256, new SecureRandom());
    return kg.generateKey();
  }
}
