namespace SimpleEncryption {
    public enum HashAlgorithm {
        SHA256,
        SHA512
    }

    public enum EncryptionAlgorithm {
        AES,
        ChaCha20,
        RSA
    }

    public enum KeyDerivationAlgorithm {
        Pbkdf2
    }
}
