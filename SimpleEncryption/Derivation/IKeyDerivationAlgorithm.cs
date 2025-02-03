namespace SimpleEncryption.Derivation {
    public interface IKeyDerivationAlgorithm {
        /// <summary> Derives a key from the input using the specified parameters. </summary>
        /// <param name="input"> The input to derive the key from. </param>
        /// <param name="parameters"> Parameters to use. </param>
        /// <returns> Derived key. </returns>
        byte[] DeriveKey(byte[]? input, KeyDerivationParameters parameters);
    }
}
