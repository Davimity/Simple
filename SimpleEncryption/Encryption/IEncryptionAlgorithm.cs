namespace SimpleEncryption.Encryption {
    public interface IEncryptionAlgorithm {
        /// <summary> Encrypts the input using the specified parameters. </summary>
        /// <param name="input"> bytes to encrypt. </param>
        /// <param name="parameters"> Parameters to use. </param>
        /// <returns> Encrypted bytes. </returns>
        byte[] Encrypt(byte[] input, EncryptionParameters parameters);

        /// <summary> Decrypts the input using the specified parameters. </summary>
        /// <param name="input"> bytes to decrypt. </param>
        /// <param name="parameters"> Parameters to use. </param>
        /// <returns> Decrypted bytes. </returns>
        byte[] Decrypt(byte[] input, EncryptionParameters parameters);
    }
}