# Encrypted Attachments — Cómo funciona (explicado fácil)

Este módulo (`com.etendoerp.encryptedattachments`) hace que los archivos adjuntos
que sube un usuario (por ejemplo un certificado, un PDF, una imagen) se guarden
**cifrados** en el disco del servidor, en vez de guardarse tal cual.

El usuario no nota nada distinto: sube y baja archivos como siempre. La magia pasa
"por debajo".

---

## 1. ¿Qué problema resuelve?

Imaginá que Etendo guarda los adjuntos en una carpeta del servidor. Hay dos riesgos:

1. **Que se filtren los datos.** Si alguien roba el disco o consigue una copia de
   la base de datos, podría abrir todos los archivos. Queremos que, sin una "llave
   maestra" que vive **fuera** de la base, esos archivos sean basura ilegible.

2. **Que un cliente vea archivos de otro.** En Etendo conviven varios *clientes*
   (tenants / empresas) en la misma instalación. Un usuario de la Empresa B **no**
   debe poder leer un archivo de la Empresa A. Ni por error, ni a propósito.

Este módulo ataca los dos problemas con **criptografía**.

---

## 2. Conceptos básicos (en criollo)

- **Cifrar (encriptar):** transformar un archivo legible en algo ilegible usando una
  *clave*. Solo con la clave correcta se puede volver a leer (**descifrar**).

- **AES-256-GCM:** el algoritmo de cifrado que usamos. Es un estándar moderno y
  seguro. El "GCM" agrega una **etiqueta de autenticación** (como un sello de
  seguridad): si intentás descifrar con la clave equivocada, o el archivo fue
  alterado, **falla en vez de devolver basura**. Esto es clave para la seguridad
  entre clientes (lo vemos abajo).

- **Clave (key):** un número secreto grande. Acá usamos claves de 256 bits.

### Envelope encryption (cifrado en sobre): KEK y DEK

En vez de una sola clave, usamos **dos niveles**. Es como una caja fuerte dentro de
otra caja fuerte:

- **DEK** (*Data Encryption Key*, "clave de datos"): es la clave que **cifra los
  archivos**. Hay **una DEK por cliente**. La de la Empresa A es distinta de la de
  la Empresa B.

- **KEK** (*Key Encryption Key*, "clave maestra"): es una clave que **cifra las
  DEK**. Hay **una sola KEK** para toda la instalación, y vive **fuera de la base de
  datos**, en el archivo `Openbravo.properties`.

¿Por qué dos niveles? Porque así:
- En la base de datos **nunca** guardamos la DEK "en limpio": guardamos la DEK ya
  cifrada con la KEK (le decimos **"DEK envuelta" / wrapped DEK**).
- Si te roban la base de datos, tenés las DEK envueltas pero **no** la KEK (que está
  en otro lado) → no podés desenvolverlas → no podés leer nada.
- Rotar (cambiar) la KEK es barato: solo hay que volver a envolver las DEK, sin tocar
  los archivos.

> **Analogía:** cada empresa tiene su llave (DEK) para abrir sus archivos. Esas llaves
> están guardadas en un cofre, y ese cofre se abre con una llave maestra (KEK) que el
> dueño se lleva a su casa (fuera de la base). Si te roban el cofre, no tenés la llave
> maestra para abrirlo.

---

## 3. ¿Cómo se logra el aislamiento entre clientes? (lo más importante)

La regla de oro del código: **la DEK se calcula siempre a partir del cliente de la
sesión actual** (`OBContext.getCurrentClient()`), **nunca** del cliente que figura en
el archivo guardado.

Entonces, si un usuario de la **Empresa B** intentara descargar un archivo de la
**Empresa A**:

1. El sistema toma la DEK de la **Empresa B** (la del que está logueado).
2. Intenta descifrar un archivo que fue cifrado con la DEK de la **Empresa A**.
3. Las claves no coinciden → la **etiqueta de autenticación de GCM falla**.
4. El sistema lanza un error ("no autorizado / no se puede descifrar") en vez de
   devolver el archivo.

Esto es **"defensa en profundidad"**: una segunda barrera de seguridad encima de la
que Etendo ya tiene (Etendo, de por sí, ya filtra los registros por cliente). Aunque
alguien lograra saltar la primera barrera, la criptografía lo frena igual.

---

## 4. ¿Qué construimos? (las piezas)

| Pieza | Qué es | Qué hace |
|---|---|---|
| `EncryptedAttachImplementation` | Una clase Java | Se "enchufa" al flujo de adjuntos de Etendo. Cuando subís un archivo, lo **cifra** antes de guardarlo; cuando lo bajás, lo **descifra**. Se registra con el nombre `ENC`. |
| `AttachmentCryptoService` | Una clase Java | El "motor" criptográfico: cifra/descifra con AES-256-GCM, carga la KEK, y genera/envuelve/desenvuelve las DEK. |
| `ETENC_Client_Key` | Una tabla nueva en la base | Guarda, por cada cliente, su **DEK envuelta** (cifrada con la KEK) más unos números de versión para futuras rotaciones de clave. |
| `EtencClientKey` | Una entidad Java | La representación en código de esa tabla (generada por Etendo). |
| Método de adjunto `ENC` | Un registro de configuración | Hace que `ENC` aparezca en la ventana *Attachment Configuration*, para activarlo por cliente. |
| Mensajes de error (AD) | Textos | Errores claros cuando falta la clave maestra, falla el desenvolver, o falla la descarga entre clientes. |

---

## 5. ¿Cómo es el flujo, paso a paso?

### Cuando subís un archivo (upload)
1. Etendo te deja subir el archivo normalmente.
2. Nuestra clase agarra el cliente de tu sesión y obtiene su **DEK**
   (si el cliente nunca subió nada, le **genera una DEK nueva** y la guarda envuelta).
3. **Cifra** el archivo con esa DEK (AES-256-GCM).
4. Guarda en el disco el archivo cifrado, con un encabezado propio:
   `ETEC | versión | versión-de-clave | IV | datos cifrados+etiqueta`.
   (El `ETEC` al principio es nuestra "firma" para reconocer el formato.)

### Cuando descargás un archivo (download)
1. Etendo localiza el archivo cifrado en disco.
2. Nuestra clase obtiene la **DEK del cliente de tu sesión**.
3. **Descifra** el archivo a un archivo temporal.
4. Te entrega ese temporal y **lo borra** apenas termina la descarga (no deja
   copias en limpio dando vueltas).

---

## 6. ¿Cómo sé que está funcionando?

- En el **disco** (`attach.path`), si mirás el archivo guardado, empieza con las
  letras `ETEC` y **no** se ve el contenido original. (Un PNG normal empezaría con
  `‰PNG`; el nuestro empieza con `ETEC`.)
- En la **base**, la tabla `ETENC_Client_Key` tiene una fila por cliente con la DEK
  envuelta (un texto en base64, ilegible sin la KEK).
- En el **log** (`openbravo.log`) aparecen líneas como:
  - `ENC upload: encrypted attachment '...' for client ... (N bytes -> M bytes...)`
  - `ENC download: decrypted attachment '...' for client ...`

---

## 7. Qué NO cubre esta primera versión (v1)

- La **llave maestra (KEK)** vive en `Openbravo.properties`. No usamos todavía un
  sistema externo de gestión de claves (KMS) ni un KeyStore de Java.
- La **rotación automática** de claves no está implementada todavía. Pero dejamos
  preparados los campos `key_version` y `kek_version` para hacerlo más adelante sin
  romper lo existente.

---

## 8. Glosario rápido

- **Tenant / Cliente:** una empresa que usa la misma instalación de Etendo, aislada
  de las demás.
- **KEK:** clave maestra, cifra las DEK, vive fuera de la base.
- **DEK:** clave por cliente, cifra los archivos.
- **Wrapped DEK:** la DEK guardada de forma cifrada (con la KEK).
- **AES-256-GCM:** el algoritmo de cifrado; el GCM detecta si la clave es la
  equivocada y falla en vez de devolver basura.
- **IV:** un valor aleatorio que se usa en cada cifrado para que dos archivos iguales
  no produzcan el mismo resultado cifrado.
- **Defensa en profundidad:** poner varias barreras de seguridad, por si una falla.
