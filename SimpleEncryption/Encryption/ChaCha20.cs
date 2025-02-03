using SimpleEncryption.Derivation;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

namespace SimpleEncryption.Encryption {

    ///<summary> Class for the ChaCha20 encryption algorithm </summary>
    ///<remarks> For empty or null input, the result will be an empty string or byte array. </remarks>

    [UnsupportedOSPlatform("browser")]
    [UnsupportedOSPlatform("ios")]
    [UnsupportedOSPlatform("tvos")]
    public static class ChaCha20 {
        #region Variables

            private static readonly ChaCha20Algorithm _algorithm = new();

        #endregion

        #region Public methods

            /// <summary> Encrypts a string using ChaCha20-Poly1305 </summary>
            /// <param name="input"> String to encrypt </param>
            /// <param name="parameters"> Encryption parameters </param>
            /// <returns> Encrypted string in Base64 format </returns>
            public static string Encrypt(string input, ChaCha20EncryptionParameters parameters) {
                if(string.IsNullOrEmpty(input)) return string.Empty;

                byte[] inputBytes = Encoding.UTF8.GetBytes(input);
                byte[] result = _algorithm.Encrypt(inputBytes, parameters);
                string sresult = Convert.ToBase64String(result);

                CryptographicOperations.ZeroMemory(inputBytes);
                CryptographicOperations.ZeroMemory(result);

                return sresult;
            }

            /// <summary> Encrypts a string using ChaCha20-Poly1305 </summary>
            /// <param name="input"> The string to encrypt </param>
            /// <param name="key"> The key. Length must be 32 bytes (256 bits) </param>
            /// <param name="nonce"> The nonce. Length must be 12 bytes (96 bits) </param>
            /// <returns> The encrypted string </returns>
            public static string Encrypt(string input, byte[] key, byte[]? nonce = null, byte[]? associatedData = null) => Encrypt(input, new ChaCha20EncryptionParameters() { Key = key, Nonce = nonce, AssociatedData = associatedData });

            /// <summary> Encrypts a byte array using ChaCha20-Poly1305 </summary>
            /// <param name="input"> The byte array to encrypt </param>
            /// <param name="parameters"> The encryption parameters </param>
            /// <returns> The encrypted byte array </returns>
            public static byte[] Encrypt(byte[] input, ChaCha20EncryptionParameters parameters) => _algorithm.Encrypt(input, parameters);

            /// <summary> Encrypts a byte array using ChaCha20-Poly1305 </summary>
            /// <param name="input"> The byte array to encrypt </param>
            /// <param name="key"> The key. Length must be 32 bytes (256 bits) </param>
            /// <param name="nonce"> The nonce. Length must be 12 bytes (96 bits) </param>
            /// <returns> The encrypted byte array </returns>
            public static byte[] Encrypt(byte[] input, byte[] key, byte[]? nonce = null, byte[]? associatedData = null) => _algorithm.Encrypt(input, new ChaCha20EncryptionParameters() { Key = key, Nonce = nonce, AssociatedData = associatedData });


            /// <summary> Decrypts a string using ChaCha20-Poly1305 </summary>
            /// <param name="input"> String to decrypt.</param>
            /// <param name="parameters"> Encryption parameters </param>
            /// <returns> Decrypted string </returns>
            public static string Decrypt(string input, ChaCha20EncryptionParameters parameters) {
                if (string.IsNullOrEmpty(input)) return string.Empty;

                byte[] inputBytes = Convert.FromBase64String(input);
                byte[] result = _algorithm.Decrypt(inputBytes, parameters);
                string sresult = Encoding.UTF8.GetString(result);

                CryptographicOperations.ZeroMemory(inputBytes);
                CryptographicOperations.ZeroMemory(result);

                return sresult;
            }

            /// <summary> Dencrypts a string using ChaCha20-Poly1305 </summary>
            /// <param name="input"> String to decrypt </param>
            /// <param name="key"> Key of 32 bytes </param>
            /// <param name="nonce"> Nonce of 12 bytes </param>
            /// <param name="associatedData"> Associated data </param>
            /// <returns>Decrypted string.</returns>
            public static string Decrypt(string input, byte[] key, byte[] nonce, byte[]? associatedData = null) => Decrypt(input, new ChaCha20EncryptionParameters() { Key = key, Nonce = nonce, AssociatedData = associatedData });

            /// <summary> Decrypts a byte array using ChaCha20-Poly1305 </summary>
            /// <param name="input"> Message to decrypt </param>
            /// <param name="parameters"> Encryption parameters </param>
            /// <returns> Dencrypted byte array </returns>
            public static byte[] Decrypt(byte[] input, ChaCha20EncryptionParameters parameters) => _algorithm.Decrypt(input, parameters);


            /// <summary> Decrypts a byte array using ChaCha20-Poly1305 </summary>
            /// <param name="input"> Message to decrypt </param>
            /// <param name="key"> Key of 32 bytes </param>
            /// <param name="nonce"> Nonce of 12 bytes </param>
            /// <param name="associatedData"> Associated data </param>
            /// <returns> Dencrypted byte array </returns>
            public static byte[] Decrypt(byte[] input, byte[] key, byte[] nonce, byte[]? associatedData = null) => _algorithm.Decrypt(input, new ChaCha20EncryptionParameters() { Key = key, Nonce = nonce, AssociatedData = associatedData });


            /// <summary> Generates a 32-byte key for ChaCha20-Poly1305.</summary>
            /// <param name="input">Input to derive the key.</param>
            /// <param name="salt">Salt to derive the key.</param>
            /// <param name="iterations">Iterations to derive the key.</param>
            /// <param name="hashAlgorithm">Hash algorithm to use.</param>
            /// <returns>Ket of 32 bytes.</returns>
            public static byte[] GenerateKey(string input, string? salt = null, int iterations = 100000, HashAlgorithmName hashAlgorithm = default) {
                if (salt == null) salt = string.Empty;
                if (hashAlgorithm == default) hashAlgorithm = HashAlgorithmName.SHA256;

                var binput = Encoding.UTF8.GetBytes(input);
                var bSalt = Encoding.UTF8.GetBytes(salt);

                try {
                    return Pbkdf2.DeriveKey(binput, bSalt, 32, iterations, hashAlgorithm);
                }
                finally {
                    CryptographicOperations.ZeroMemory(binput);
                    CryptographicOperations.ZeroMemory(bSalt);
                }
            }

            /// <summary>Generates a 32-byte key for ChaCha20-Poly1305.</summary>
            /// <param name="input">Input to derive the key.</param>
            /// <param name="salt">Salt to derive the key.</param>
            /// <param name="iterations">Number of iterations to derive the key.</param>
            /// <param name="hashAlgorithm">Hash algorithm to use.</param>
            /// <returns>Ket of 32 bytes.</returns>
            public static byte[] GenerateKey(byte[] input, byte[]? salt = null, int iterations = 100000, HashAlgorithmName hashAlgorithm = default) {
                if (salt == null) salt = Array.Empty<byte>();
                if (hashAlgorithm == default) hashAlgorithm = HashAlgorithmName.SHA256;

                return Pbkdf2.DeriveKey(input, salt, 32, iterations, hashAlgorithm);
            }


            /// <summary>Gnerates a 12-byte nonce for ChaCha20-Poly1305.</summary>
            /// <returns>Nonce of 12 bytes.</returns>
            public static byte[] GenerateNonce() {
                var nonce = new byte[12];

                try {
                    using (var rng = RandomNumberGenerator.Create()) {
                        rng.GetBytes(nonce);
                    }
                }
                catch {
                    CryptographicOperations.ZeroMemory(nonce);
                    throw;
                }

                return nonce;
            }

        #endregion
    }

    ///<summary> Parameters for the ChaCha20 encryption algorithm, checks if key and nonce are not null and have the right length. </summary>
    ///<remarks> Initially, key and IV are null. Use the dispose method to clear the data (key, IV and associated data will be set to null). </remarks>
    public class ChaCha20EncryptionParameters : EncryptionParameters{
        #region Variables

            private byte[]? _key;
            private byte[]? _nonce;

        #endregion  

        #region Properties

            /// <summary> The key to use, the length must be 32 bytes (256 bits). </summary>
            public byte[]? Key {
                get => _key;
                set {
                    if (value == null || value.Length != 32) throw new ArgumentException("Key must have 32 bytes.");
                    _key = (byte[])value.Clone();
                }
            }

            /// <summary> The initialization vector to use, the length must be 12 bytes (96 bits). </summary>
            public byte[]? Nonce {
                get => _nonce;
                set {
                    if (value == null || value.Length != 12) throw new ArgumentException($"Nonce must have 12 bytes.");
                    _nonce = (byte[])value.Clone();
                }
            }

            /// <summary> The associated data to use. </summary>/
            public byte[]? AssociatedData;

        #endregion

        #region Public methods

            public override void Dispose() {
                if(_key != null) {
                    CryptographicOperations.ZeroMemory(_key);
                    _key = null;
                }

                if (_nonce != null) {
                    CryptographicOperations.ZeroMemory(_nonce);
                    _nonce = null;
                }

                if (AssociatedData != null) {
                    CryptographicOperations.ZeroMemory(AssociatedData);
                    AssociatedData = null;
                }                 
            }

        #endregion
    }


    ///<summary> Implementation of the ChaCha20 encryption algorithm </summary>
    ///<remarks> For empty or null input, the result will be an empty byte array. </remarks>

    [UnsupportedOSPlatform("browser")]
    [UnsupportedOSPlatform("ios")]
    [UnsupportedOSPlatform("tvos")]
    public class ChaCha20Algorithm : IEncryptionAlgorithm {
        public byte[] Encrypt(byte[] input, EncryptionParameters parameters) {
            if (input == null || input.Length == 0) return Array.Empty<byte>();
            if (parameters is not ChaCha20EncryptionParameters chaCha20Params) throw new ArgumentException("Parameters must be of type ChaCha20EncryptionParameters.");
            if (chaCha20Params.Key == null) throw new ArgumentException("Key cannot be null.");

            byte[]? associatedDataCopy = null;
            byte[]? keyCopy = null;
            byte[]? nonceCopy = null;

            try {
                if (chaCha20Params.AssociatedData != null) {
                    associatedDataCopy = new byte[chaCha20Params.AssociatedData.Length];
                    Buffer.BlockCopy(chaCha20Params.AssociatedData, 0, associatedDataCopy, 0, chaCha20Params.AssociatedData.Length);
                }

                keyCopy = new byte[chaCha20Params.Key.Length];
                Buffer.BlockCopy(chaCha20Params.Key, 0, keyCopy, 0, chaCha20Params.Key.Length);

                if (chaCha20Params.Nonce == null) nonceCopy = ChaCha20.GenerateNonce();
                else {
                    nonceCopy = new byte[chaCha20Params.Nonce.Length];
                    Buffer.BlockCopy(chaCha20Params.Nonce, 0, nonceCopy, 0, chaCha20Params.Nonce.Length);
                }

                var ciphertext = new byte[input.Length];
                var tag = new byte[16];

                using (var cipher = new ChaCha20Poly1305(keyCopy)) {
                    cipher.Encrypt(nonceCopy, input, ciphertext, tag, associatedDataCopy);
                }

                var result = new byte[nonceCopy.Length + tag.Length + ciphertext.Length];
                Buffer.BlockCopy(nonceCopy, 0, result, 0, nonceCopy.Length);
                Buffer.BlockCopy(tag, 0, result, nonceCopy.Length, tag.Length);
                Buffer.BlockCopy(ciphertext, 0, result, nonceCopy.Length + tag.Length, ciphertext.Length);

                CryptographicOperations.ZeroMemory(ciphertext);
                CryptographicOperations.ZeroMemory(tag);

                return result;
            }
            finally {
                if (keyCopy != null) CryptographicOperations.ZeroMemory(keyCopy);
                if (nonceCopy != null) CryptographicOperations.ZeroMemory(nonceCopy);
                if (associatedDataCopy != null) CryptographicOperations.ZeroMemory(associatedDataCopy);

                keyCopy = null;
                nonceCopy = null;
                associatedDataCopy = null;
            }
        }
        public byte[] Decrypt(byte[] input, EncryptionParameters parameters) {
            if (input == null || input.Length == 0) return Array.Empty<byte>();
            if (parameters is not ChaCha20EncryptionParameters chaCha20Params) throw new ArgumentException("Parameters must be of type ChaCha20EncryptionParameters.");
            if (chaCha20Params.Key == null) throw new ArgumentException("Key cannot be null.");

            byte[]? associatedDataCopy = null;
            byte[]? keyCopy = null;

            try {
                if (chaCha20Params.AssociatedData != null) {
                    associatedDataCopy = new byte[chaCha20Params.AssociatedData.Length];
                    Buffer.BlockCopy(chaCha20Params.AssociatedData, 0, associatedDataCopy, 0, chaCha20Params.AssociatedData.Length);
                }

                keyCopy = new byte[chaCha20Params.Key.Length];
                Buffer.BlockCopy(chaCha20Params.Key, 0, keyCopy, 0, chaCha20Params.Key.Length);

                int nonceLength = 12;
                int tagLength = 16;

                int ciphertextLength = input.Length - nonceLength - tagLength;

                byte[] nonce = new byte[nonceLength];
                byte[] tag = new byte[tagLength];
                byte[] ciphertext = new byte[ciphertextLength];

                Buffer.BlockCopy(input, 0, nonce, 0, nonceLength);
                Buffer.BlockCopy(input, nonceLength, tag, 0, tagLength);
                Buffer.BlockCopy(input, nonceLength + tagLength, ciphertext, 0, ciphertextLength);

                byte[] plaintext = new byte[ciphertextLength];

                using (var cipher = new ChaCha20Poly1305(keyCopy)) {
                    cipher.Decrypt(nonce, ciphertext, tag, plaintext, associatedDataCopy);
                }

                CryptographicOperations.ZeroMemory(nonce);
                CryptographicOperations.ZeroMemory(tag);
                CryptographicOperations.ZeroMemory(ciphertext);

                return plaintext;
            }
            finally {
                if (keyCopy != null) CryptographicOperations.ZeroMemory(keyCopy);
                if (associatedDataCopy != null) CryptographicOperations.ZeroMemory(associatedDataCopy);

                keyCopy = null;
                associatedDataCopy = null;
            }
        }
    }
}
