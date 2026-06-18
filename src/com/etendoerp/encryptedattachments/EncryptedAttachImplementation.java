/*
 * Copyright 2026 Futit Services S.L.
 *
 * Licensed under the Etendo License Version 1.0.
 * You may not use this file except in compliance with the License.
 * You may find a copy of the License at:
 * https://github.com/etendosoftware/etendo_core/blob/main/legal/Etendo_license.txt
 */
package com.etendoerp.encryptedattachments;

import java.io.File;
import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Map;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openbravo.base.exception.OBException;
import org.openbravo.client.application.attachment.CoreAttachImplementation;
import org.openbravo.client.kernel.ComponentProvider;
import org.openbravo.dal.core.OBContext;
import org.openbravo.model.ad.system.Client;
import org.openbravo.model.ad.utility.Attachment;

import com.etendoerp.encryptedattachments.AttachmentCryptoService.ClientDek;

/**
 * Encrypted attachment method ("ENC"). Reuses the core filesystem layout
 * (directory structure, path resolution) by extending
 * {@link CoreAttachImplementation}, and intercepts only the file content to
 * apply per-client AES-256-GCM envelope encryption.
 *
 * <p>Tenant isolation is cryptographic: the DEK is always derived from the
 * session client ({@link OBContext#getCurrentClient()}), never from the stored
 * attachment. A cross-client download decrypts with the wrong DEK, the GCM
 * authentication tag fails, and access is denied.
 */
@ApplicationScoped
@ComponentProvider.Qualifier(EncryptedAttachImplementation.ENC_METHOD)
public class EncryptedAttachImplementation extends CoreAttachImplementation {

  public static final String ENC_METHOD = "ENC";

  private static final Logger log = LogManager.getLogger();

  @Inject
  private AttachmentCryptoService cryptoService;

  @Override
  public void uploadFile(Attachment attachment, String dataType, Map<String, Object> parameters,
      File file, String tabId) throws OBException {
    Client client = OBContext.getOBContext().getCurrentClient();
    ClientDek dek = cryptoService.getOrCreateDek(client);

    try {
      byte[] plaintext = Files.readAllBytes(file.toPath());
      byte[] encrypted = cryptoService.encrypt(plaintext, dek.getKey(), dek.getKeyVersion());
      // Overwrite the source file in place; its name equals attachment.getName(),
      // so the core upload (copy + path bookkeeping) keeps working unchanged.
      Files.write(file.toPath(), encrypted);
      log.info("ENC upload: encrypted attachment '{}' for client {} ({} bytes -> {} bytes, keyVersion {})",
          attachment.getName(), client.getId(), plaintext.length, encrypted.length, dek.getKeyVersion());
    } catch (IOException e) {
      throw new OBException("Failed to encrypt attachment " + attachment.getName(), e);
    }

    // Delegate to core: copies the (now encrypted) file to attach.path and sets the path.
    super.uploadFile(attachment, dataType, parameters, file, tabId);
  }

  @Override
  public File downloadFile(Attachment attachment) throws OBException {
    // Core returns the File pointing to the encrypted bytes on disk.
    File encryptedFile = super.downloadFile(attachment);
    if (!encryptedFile.exists()) {
      return encryptedFile; // let the manager handle the not-found case
    }

    Client client = OBContext.getOBContext().getCurrentClient();
    ClientDek dek = cryptoService.getOrCreateDek(client);

    try {
      byte[] encrypted = Files.readAllBytes(encryptedFile.toPath());
      // Throws OBException (GCM tag failure) when the current client's DEK does
      // not match the one used to encrypt — this is the cross-client guard.
      byte[] plaintext = cryptoService.decrypt(encrypted, dek.getKey());

      // Write the decrypted content to its own temp subdirectory so the manager's
      // deleteTempFile() removes both the file and the directory afterwards.
      File tempDir;
      if (FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
        tempDir = Files.createTempDirectory("etenc-",
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"))).toFile();
      } else {
        tempDir = Files.createTempDirectory("etenc-").toFile(); //NOSONAR permissions set below
        boolean revokeRead = tempDir.setReadable(false, false);
        boolean revokeWrite = tempDir.setWritable(false, false);
        boolean revokeExec = tempDir.setExecutable(false, false);
        boolean grantRead = tempDir.setReadable(true, true);
        boolean grantWrite = tempDir.setWritable(true, true);
        boolean grantExec = tempDir.setExecutable(true, true);
        if (!(revokeRead && revokeWrite && revokeExec && grantRead && grantWrite && grantExec)) {
          log.warn("ENC: could not fully restrict temp dir permissions on non-POSIX filesystem");
        }
      }
      File decrypted = new File(tempDir, attachment.getName());
      Files.write(decrypted.toPath(), plaintext);
      log.info("ENC download: decrypted attachment '{}' for client {} ({} bytes -> {} bytes)",
          attachment.getName(), client.getId(), encrypted.length, plaintext.length);
      return decrypted;
    } catch (IOException e) {
      throw new OBException("Failed to decrypt attachment " + attachment.getName(), e);
    }
  }

  @Override
  public boolean isTempFile() {
    // The downloaded file is a decrypted temporary copy and must be removed.
    return true;
  }
}
