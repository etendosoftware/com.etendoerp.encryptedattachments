# Encrypted Attachments

Transparently encrypts files uploaded to Etendo using AES-256-GCM with per-client keys. Users upload and download files as usual — encryption and decryption happen automatically in the background.

---

## Requirements

- Etendo Core with attachment support enabled
- Java 17+
- Write access to `gradle.properties`

---

## Installation

Install the module through the standard Etendo module installation process or add it to your `build.gradle` dependencies:

```groovy
implementation("com.etendoerp:encryptedattachments:1.0.0")
```

Then run smartbuild to deploy.

---

## Configuration

### 1. Set the master key

Add the following property to `gradle.properties`:

```properties
attachment.encryption.masterkey=<your-256-bit-key-in-base64>
```

To generate a secure key:

```bash
openssl rand -base64 32
```

> **Important:** This key must never be stored in the database. Keep it in `gradle.properties` only. Without it, encrypted attachments cannot be decrypted.

### 2. Enable the attachment method

1. Go to **General Setup > Application > Attachment Configuration**
2. Create a new record (or edit an existing one) for the target client
3. Set **Attachment Method** to `ENC`
4. Save

From this point on, all new attachments uploaded by that client will be encrypted automatically.

---

## Usage

No changes are required for end users. The `ENC` method is fully transparent:

- **Upload:** attach a file as usual from any Etendo window. The file is encrypted before being written to disk.
- **Download:** open or download the attachment as usual. The file is decrypted on the fly and the plaintext copy is discarded immediately after delivery.

---

## Verifying it works

**On disk** — navigate to your `attach.path` directory. Encrypted files start with the magic bytes `ETEC` instead of their original format header (e.g. a PNG would normally start with `‰PNG`).

**In the database** — the table `ETENC_Client_Key` contains one row per client with its encrypted DEK (a base64 string). If this table is empty, no files have been encrypted yet.

**In the logs** — `gradle.log` will contain entries like:

```
ENC upload: encrypted attachment 'invoice.pdf' for client Acme Corp (42301 bytes -> 42333 bytes)
ENC download: decrypted attachment 'invoice.pdf' for client Acme Corp
```

---

## Cross-client isolation

Each client uses a unique encryption key (DEK). A file encrypted for Client A cannot be decrypted using Client B's session — the authentication tag built into AES-GCM will fail and the download will be rejected. This is a second layer of isolation on top of Etendo's standard record-level access control.

---

## Known limitations

- **Key management:** the master key (KEK) lives in `gradle.properties`. External KMS or Java KeyStore integration is not supported in this version.
- **Key rotation:** manual rotation of the master key is not yet supported. The `key_version` and `kek_version` fields in `ETENC_Client_Key` are reserved for a future rotation feature.
- **Existing attachments:** files uploaded before enabling the `ENC` method are not retroactively encrypted.
