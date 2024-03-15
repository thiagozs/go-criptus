# Criptus - Symmetric and Asymmetric Encryption

**Criptus** provides an interface for both symmetric encryption (AES/DES/3DES) and asymmetric encryption (RSA and ECDSA), simplifying the process of securing your sensitive data for storage and transmission.

## AES Encryption

Criptus supports various key lengths for AES encryption: AES-128, AES-192, and AES-256. You can also choose from several encryption modes, including CBC, CFB, CTR, and OFB, with plans to support additional modes in the future.

To use AES encryption, you need to provide:

- `specialSign`: A unique signature for the encryption process.
- `key`: The encryption key. It is recommended to use a key of appropriate length according to the chosen AES variant (128, 192, or 256 bits).
- `iv`: The initialization vector, fixed at 16 bytes. If not provided, it defaults to the first 16 bytes of the concatenation of `specialSign` and `key`.

## DES and 3DES Encryption

DES (Data Encryption Standard) is a symmetric-key algorithm for encrypting electronic data. Despite its age, DES continues to influence modern encryption schemes. However, due to its 56-bit key size, DES is considered insecure for many applications. 3DES (Triple DES) enhances DES's security by applying the encryption process three times with three different keys, effectively extending the key length and improving security. Criptus supports both DES and 3DES encryption, providing a balance between compatibility with legacy systems and enhanced security.

## RSA Encryption

RSA is a widely-used asymmetric encryption algorithm that enables secure data transmission. Unlike symmetric algorithms, RSA uses a pair of keys: a public key for encryption and a private key for decryption. This key pair mechanism facilitates secure data exchange and digital signatures, making RSA a cornerstone of modern secure communication. Criptus incorporates RSA encryption, allowing users to leverage its robust security to protect sensitive information.

## ECDSA Encryption

ECDSA (Elliptic Curve Digital Signature Algorithm) is a digital signature algorithm that uses elliptic curve cryptography to offer a high level of security with smaller key sizes, making it efficient for applications with performance and space constraints. In the financial sector, where efficiency and security are paramount, ECDSA is often used for authentication and to ensure the integrity and non-repudiation of transactions. Criptus supports ECDSA, providing a powerful option for asymmetric encryption and digital signatures.

-----

## Versioning and License

Our version numbers follow the [semantic versioning specification](http://semver.org/). You can see the available versions by checking the [tags on this repository](https://github.com/thiagozs/go-criptus/tags). For more details about our license model, please take a look at the [LICENSE.md](LICENSE.md) file.

**2024**, thiagozs.
