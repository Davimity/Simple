namespace SimpleEncryption.Hashing {
    public interface IHashAlgorithm {
        /// <summary> Hashes the input using the specified parameters. </summary>
        /// <param name="input"> The input to hash. </param>
        /// <param name="parameters"> Parameters to use. </param>
        /// <returns> Hashed input. </returns>
        byte[] Hash(byte[] input, HashParameters parameters);
    }
}
