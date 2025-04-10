using SimpleEncryption.Derivation;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

using SAes = System.Security.Cryptography.Aes;

namespace SimpleEncryption.Encryption {

    ///<summary> Cipher modes for the Aes encryption algorithm </summary>
    public enum AesCipherMode {
        CBC = 1,
        ECB = 2,
        OFB = 3,
        CFB = 4,   
        CTS = 5,
        GCM = 6
    }


    ///<summary> Class for the Aes encryption algorithm </summary>
    ///<remarks> For empty or null input, the result will be an empty string or byte array. </remarks>

    [UnsupportedOSPlatform("browser")]
    public static class Aes{
        #region Variables

            private static readonly AesAlgorithm _algorithm = new();

        #endregion

        #region Public methods

            /// <summary> Encrypts a string using AES encryption </summary>
            /// <param name="input"> The string to encrypt </param>
            /// <param name="parameters"> The encryption parameters </param>
            /// <returns> The encrypted string </returns>
            public static string Encrypt(string input, AesEncryptionParameters parameters) {
                if (string.IsNullOrEmpty(input)) return string.Empty;

                byte[] inputBytes = Encoding.UTF8.GetBytes(input);
                byte[] result = _algorithm.Encrypt(inputBytes, parameters);
                string sresult = Convert.ToBase64String(result);    

                CryptographicOperations.ZeroMemory(inputBytes);
                CryptographicOperations.ZeroMemory(result);

                return sresult;
            }

            /// <summary> Encrypts a string using AES encryption </summary>
            /// <param name="input"> The string to encrypt </param>
            /// <param name="key"> The key </param>
            /// <param name="iv"> The initialization vector </param>
            /// <returns> The encrypted string </returns>
            public static string Encrypt(string input, byte[] key, byte[] iv) => Encrypt(input, new AesEncryptionParameters() { Key = key, IV = iv });

            /// <summary> Encrypts a byte array using AES encryption </summary>
            /// <param name="input"> The byte array to encrypt </param>
            /// <param name="parameters"> The encryption parameters </param>
            /// <returns> The encrypted byte array </returns>
            public static byte[] Encrypt(byte[] input, AesEncryptionParameters parameters) => _algorithm.Encrypt(input, parameters);

            /// <summary> Encrypts a byte array using AES encryption </summary>
            /// <param name="input"> The byte array to encrypt </param>
            /// <param name="key"> The key </param>
            /// <param name="iv"> The initialization vector </param>
            /// <returns> The encrypted byte array </returns>
            public static byte[] Encrypt(byte[] input, byte[] key, byte[] iv) => _algorithm.Encrypt(input, new AesEncryptionParameters() { Key = key, IV = iv });


            /// <summary> Decrypts a string using AES encryption </summary>
            /// <param name="input"> The string to decrypt </param>
            /// <param name="parameters"> The encryption parameters </param>
            /// <return> The decrypted string </return>
            public static string Decrypt(string input, AesEncryptionParameters parameters) {
                if (string.IsNullOrEmpty(input)) return string.Empty;

                byte[] inputBytes = Convert.FromBase64String(input);
                byte[] result = _algorithm.Decrypt(inputBytes, parameters);
                string sresult = Encoding.UTF8.GetString(result);

                CryptographicOperations.ZeroMemory(inputBytes);
                CryptographicOperations.ZeroMemory(result);

                return sresult;
            }

            /// <summary> Decrypts a string using AES encryption </summary>
            /// <param name="input"> The string to decrypt </param>
            /// <param name="key"> The key </param>
            /// <param name="iv"> The initialization vector </param>
            /// <return> The decrypted string </return>
            public static string Decrypt(string input, byte[] key, byte[] iv) => Decrypt(input, new AesEncryptionParameters() { Key = key, IV = iv });

            /// <summary> Decrypts a byte array using AES encryption </summary>
            /// <param name="input"> The byte array to encrypt </param>
            /// <param name="parameters"> The encryption parameters </param>
            /// <returns> The decrypted byte array </returns>
            public static byte[] Decrypt(byte[] input, AesEncryptionParameters parameters) => _algorithm.Decrypt(input, parameters);

            /// <summary> Decrypts a byte array using AES encryption </summary>
            /// <param name="input"> The byte array to encrypt </param>
            /// <param name="key"> The key </param>
            /// <param name="iv"> The initialization vector </param>
            /// <returns> The decrypted byte array </returns>
            public static byte[] Decrypt(byte[] input, byte[] key, byte[] iv) => _algorithm.Decrypt(input, new AesEncryptionParameters() { Key = key, IV = iv });


            /// <summary> Generates a key for AES encryption </summary>
            /// <param name="input"> The input string </param>
            /// <param name="salt"> The salt string </param>
            /// <param name="keySize"> The size of the key in bytes </param>
            /// <param name="iterations"> The number of iterations to generate the key </param>
            /// <param name="hashAlgorithm"> The hash algorithm to use </param>
            /// <returns> The generated key </returns>
            public static byte[] GenerateKey(string input, string? salt = null, int keySize = 32, int iterations = 100000, HashAlgorithmName hashAlgorithm = default) {
                if(salt == null) salt = string.Empty;
                if (hashAlgorithm == default) hashAlgorithm = HashAlgorithmName.SHA256;

                var binput = Encoding.UTF8.GetBytes(input);
                var bSalt = Encoding.UTF8.GetBytes(salt);

                try {
                    return Pbkdf2.DeriveKey(binput, bSalt, keySize, iterations, hashAlgorithm);
                }
                finally {
                    CryptographicOperations.ZeroMemory(binput);
                    CryptographicOperations.ZeroMemory(bSalt);
                }
            }

            /// <summary> Generates a key for AES encryption </summary>
            /// <param name="input"> The input byte[] </param>
            /// <param name="salt"> The salt byte[] </param>
            /// <param name="keySize"> The size of the key in bytes </param>
            /// <param name="iterations"> The number of iterations to generate the key </param>
            /// <param name="hashAlgorithm"> The hash algorithm to use </param>
            /// <returns> The generated key </returns>
            public static byte[] GenerateKey(byte[] input, byte[]? salt = null, int keySize = 32, int iterations = 100000, HashAlgorithmName hashAlgorithm = default) {
                if (salt == null) salt = Array.Empty<byte>();
                if (hashAlgorithm == default) hashAlgorithm = HashAlgorithmName.SHA256;

                return Pbkdf2.DeriveKey(input, salt, keySize, iterations, hashAlgorithm);
            }


            /// <summary> Generates an initialization vector for AES encryption </summary>
            /// <param name="input"> The input string </param>
            /// <param name="salt"> The salt string </param>
            /// <param name="ivSize"> The size of the key in bytes </param>
            /// <param name="iterations"> The number of iterations to generate the IV </param>
            /// <param name="hashAlgorithm"> The hash algorithm to use </param>
            /// <returns> The generated IV </returns>
            public static byte[] GenerateIv(string input, string? salt = null, int ivSize = 12, int iterations = 100000, HashAlgorithmName hashAlgorithm = default) {
                if(salt == null) salt = string.Empty;
                if (hashAlgorithm == default) hashAlgorithm = HashAlgorithmName.SHA256;

                var binput = Encoding.UTF8.GetBytes(input);
                var bSalt = Encoding.UTF8.GetBytes(salt);

                try {
                    return Pbkdf2.DeriveKey(binput, bSalt, ivSize, iterations, hashAlgorithm);
                }
                finally {
                    CryptographicOperations.ZeroMemory(binput);
                    CryptographicOperations.ZeroMemory(bSalt);
                }
            }

            /// <summary> Generates an initialization vector for AES encryption </summary>
            /// <param name="input"> The input byte[] </param>
            /// <param name="salt"> The salt byte[] </param>
            /// <param name="ivSize"> The size of the key in bytes </param>
            /// <param name="iterations"> The number of iterations to generate the IV </param>
            /// <param name="hashAlgorithm"> The hash algorithm to use </param>
            /// <returns> The generated IV </returns>
            public static byte[] GenerateIv(byte[] input, byte[]? salt = null, int ivSize = 12, int iterations = 100000, HashAlgorithmName hashAlgorithm = default) {
                if (salt == null) salt = Array.Empty<byte>();
                if (hashAlgorithm == default) hashAlgorithm = HashAlgorithmName.SHA256;

                return Pbkdf2.DeriveKey(input, salt, ivSize, iterations, hashAlgorithm);
            }

        #endregion
    }


    ///<summary> Parameters for the Aes encryption algorithm, checks if key size and iterations are greater than 0 and divsors of 8, if key and IV are not null and if key size is equal to key length. </summary>
    ///<remarks> Initially, key and IV are null. Use the dispose method to clear the data (key and IV will be set to null and key size and block size will be set to 0). Default key size is 256 bits (32 bytes) and block size 128 bits (16 bytes) </remarks>
    public class AesEncryptionParameters : EncryptionParameters {
        #region Variables

            private byte[]? _key;
            private byte[]? _iv;
            private int _keySize = 256;
            private int _blockSize = 128;

            private int hmacIterations = 100000;

        #endregion

        #region Properties

            /// <summary> The cipher mode to use. </summary>
            public AesCipherMode CipherMode = AesCipherMode.GCM;

            /// <summary> The padding mode to use. </summary>
            public PaddingMode PaddingMode = PaddingMode.PKCS7;

            /// <summary> Boolean to indicate if HMAC is used. Not necessary for GCM mode. </summary>
            public bool UseHmac { get; set; } = false;

            /// <summary> The HMAC key to use. </summary>
            public HashAlgorithmName HmacHashAlgorithm { get; set; } = HashAlgorithmName.SHA512;

            /// <summary> The number of iterations to use for HMAC. </summary>
            public int HmacIterations {
                get => hmacIterations;
                set {
                    if (value <= 0) throw new ArgumentException("HMAC iterations must be greater than 0.");
                    hmacIterations = value;
                }
            }

            /// <summary> The salt to use for HMAC. </summary>
            /// <remarks> This is not used in GCM mode. If null, default hmac salt will be used. </remarks>
            public byte[]? HmacSalt = null;

            /// <summary> The key to use, it must be equal to the key size (in bits) divided by 8. </summary>
            public byte[]? Key {
                get => _key;
                set {
                    if (value == null || value.Length != (_keySize / 8)) throw new ArgumentException($"Key must have {_keySize / 8} bytes.");
                    _key = (byte[])value.Clone();
                }
            }

            /// <summary> The initialization vector to use, it must be equal to the block size (in bits) divided by 8. </summary>
            public byte[]? IV {
                get => _iv;
                set {
                    if (value == null) throw new ArgumentException("IV cannot be null.");

                    if (CipherMode == AesCipherMode.GCM && value.Length != 12) throw new ArgumentException("For AES-GCM, IV must be 12 bytes.");
                    else if(CipherMode != AesCipherMode.GCM && value.Length != _blockSize / 8) throw new ArgumentException($"IV must have {_blockSize / 8} bytes for {CipherMode} cipher mode.");
                    
                    _iv = (byte[])value.Clone();
                }
            }

        /// <summary> The size of the key in bits. </summary>
        public int KeySize {
                get => _keySize;
                set {
                    if (value != 128 && value != 192 && value != 256) throw new ArgumentException("Key size must be 128, 192, or 256 bits for AES.");
                    _keySize = value;
                }
            }

            /// <summary> The size of the block in bits. </summary>
            public int BlockSize {
                get => _blockSize;
            }

        #endregion

        #region Public methods

            public override void Dispose() {
                if (_key != null) {
                    CryptographicOperations.ZeroMemory(_key);
                    _key = null;
                }

                if (_iv != null) {
                    CryptographicOperations.ZeroMemory(_iv);
                    _iv = null;
                }

                _keySize = 0;
                _blockSize = 0;
            }

        #endregion
    }


    ///<summary> Implementation of the Aes encryption algorithm </summary>
    ///<remarks> For empty or null input, the result will be an empty byte array. </remarks>

    [UnsupportedOSPlatform("browser")]
    public class AesAlgorithm : IEncryptionAlgorithm {
        #region Public methods

            public byte[] Encrypt(byte[] input, EncryptionParameters parameters) {
                if (input == null || input.Length == 0) return Array.Empty<byte>();
                if (parameters is not AesEncryptionParameters aesParams) throw new ArgumentException("Parameters must be of type AesEncryptionParameters.");
                if(aesParams.Key == null || aesParams.IV == null) throw new ArgumentException("Key and IV cannot be null.");

                if(aesParams.CipherMode == AesCipherMode.GCM) return EncryptGCM(input, aesParams);

                byte[]? keyCopy = null;
                byte[]? ivCopy = null;

                try {
                    keyCopy = new byte[aesParams.Key.Length];
                    Buffer.BlockCopy(aesParams.Key, 0, keyCopy, 0, aesParams.Key.Length);
                    ivCopy = new byte[aesParams.IV.Length];
                    Buffer.BlockCopy(aesParams.IV, 0, ivCopy, 0, aesParams.IV.Length);

                    using var aes = SAes.Create();
                    aes.KeySize = aesParams.KeySize;
                    aes.BlockSize = aesParams.BlockSize;
                    aes.Mode = (CipherMode)aesParams.CipherMode;
                    aes.Padding = aesParams.PaddingMode;

                    aes.Key = keyCopy;
                    aes.IV = ivCopy;

                    byte[] encryptedData;
                    using (var encryptor = aes.CreateEncryptor())
                    using (var ms = new MemoryStream())
                    using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write)) {
                        cs.Write(input, 0, input.Length);
                        cs.FlushFinalBlock();
                        encryptedData = ms.ToArray();
                    }

                    CryptographicOperations.ZeroMemory(keyCopy);
                    CryptographicOperations.ZeroMemory(ivCopy);

                    keyCopy = null;
                    ivCopy = null;

                    if (aesParams.UseHmac) {
                        byte[] derivedHmacKey = Pbkdf2.DeriveKey(aesParams.Key, aesParams.HmacSalt ?? Encoding.UTF8.GetBytes("AES-HMAC"), aesParams.Key.Length, aesParams.HmacIterations, aesParams.HmacHashAlgorithm);

                        byte[] dataToMac = new byte[aesParams.IV.Length + encryptedData.Length];
                        Buffer.BlockCopy(aesParams.IV, 0, dataToMac, 0, aesParams.IV.Length);
                        Buffer.BlockCopy(encryptedData, 0, dataToMac, aesParams.IV.Length, encryptedData.Length);

                        byte[] macTag;
                        using (var hmac = new HMACSHA256(derivedHmacKey)) {
                            macTag = hmac.ComputeHash(dataToMac);
                        }

                        byte[] result = new byte[dataToMac.Length + macTag.Length];
                        Buffer.BlockCopy(dataToMac, 0, result, 0, dataToMac.Length);
                        Buffer.BlockCopy(macTag, 0, result, dataToMac.Length, macTag.Length);

                        CryptographicOperations.ZeroMemory(dataToMac);
                        CryptographicOperations.ZeroMemory(derivedHmacKey);
                        CryptographicOperations.ZeroMemory(macTag);

                        return result;
                    }

                    return encryptedData;
                }
                finally {
                    if (keyCopy != null) CryptographicOperations.ZeroMemory(keyCopy);
                    if (ivCopy != null) CryptographicOperations.ZeroMemory(ivCopy);

                    keyCopy = null;
                    ivCopy = null;
                }
            }

            public byte[] Decrypt(byte[] input, EncryptionParameters parameters) {
                if (input == null || input.Length == 0) return Array.Empty<byte>();
                if (parameters is not AesEncryptionParameters aesParams) throw new ArgumentException("Parameters must be of type AesEncryptionParameters.");
                if (aesParams.Key == null || aesParams.IV == null)  throw new ArgumentException("Key and IV cannot be null.");

                if (aesParams.CipherMode == AesCipherMode.GCM) return DecryptGCM(input, aesParams);

                byte[] dataForDecryption;

                if (aesParams.UseHmac) {
                    if (input.Length < aesParams.IV.Length + 32) throw new ArgumentException("Invalid input length for decryption with HMAC.");

                    int ciphertextLength = input.Length - aesParams.IV.Length - 32;
                    byte[] ivFromInput = new byte[aesParams.IV.Length];
                    byte[] ciphertext = new byte[ciphertextLength];
                    byte[] macTag = new byte[32];

                    Buffer.BlockCopy(input, 0, ivFromInput, 0, ivFromInput.Length);
                    Buffer.BlockCopy(input, ivFromInput.Length, ciphertext, 0, ciphertextLength);
                    Buffer.BlockCopy(input, ivFromInput.Length + ciphertextLength, macTag, 0, 32);

                    byte[] dataToMac = new byte[ivFromInput.Length + ciphertext.Length];
                    Buffer.BlockCopy(ivFromInput, 0, dataToMac, 0, ivFromInput.Length);
                    Buffer.BlockCopy(ciphertext, 0, dataToMac, ivFromInput.Length, ciphertext.Length);

                    byte[] derivedHmacKey = Pbkdf2.DeriveKey(aesParams.Key, aesParams.HmacSalt ?? Encoding.UTF8.GetBytes("AES-HMAC"), aesParams.Key.Length, aesParams.HmacIterations, aesParams.HmacHashAlgorithm);

                    byte[] computedMac;
                    using (var hmac = new HMACSHA256(derivedHmacKey)) {
                        computedMac = hmac.ComputeHash(dataToMac);
                    }

                    if (!CryptographicOperations.FixedTimeEquals(macTag, computedMac))
                        throw new CryptographicException("The message has been modified or authentication failed.");

                    CryptographicOperations.ZeroMemory(dataToMac);
                    CryptographicOperations.ZeroMemory(computedMac); 
                    CryptographicOperations.ZeroMemory(derivedHmacKey);
                    CryptographicOperations.ZeroMemory(macTag);
                   
                    aesParams.IV = ivFromInput;
                    dataForDecryption = ciphertext;
                }
                else {
                    dataForDecryption = input;
                }

                byte[]? keyCopy = null;
                byte[]? ivCopy = null;
                try {
                    keyCopy = new byte[aesParams.Key.Length];
                    Buffer.BlockCopy(aesParams.Key, 0, keyCopy, 0, aesParams.Key.Length);
                    ivCopy = new byte[aesParams.IV.Length];
                    Buffer.BlockCopy(aesParams.IV, 0, ivCopy, 0, aesParams.IV.Length);

                    using var aes = SAes.Create();
                    aes.KeySize = aesParams.KeySize;
                    aes.BlockSize = aesParams.BlockSize;
                    aes.Mode = (CipherMode)aesParams.CipherMode;
                    aes.Padding = aesParams.PaddingMode;

                    aes.Key = keyCopy;
                    aes.IV = ivCopy;

                    byte[] decryptedData;
                    using (var decryptor = aes.CreateDecryptor())
                    using (var ms = new MemoryStream(dataForDecryption))
                    using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    using (var resultStream = new MemoryStream()) {
                        cs.CopyTo(resultStream);
                        decryptedData = resultStream.ToArray();
                    }
                    return decryptedData;
                }
                finally {
                    if (keyCopy != null) {
                        CryptographicOperations.ZeroMemory(keyCopy);
                        keyCopy = null;
                    }
                    if (ivCopy != null) {
                        CryptographicOperations.ZeroMemory(ivCopy);
                        ivCopy = null;
                    }
                }
            }

        #endregion

        #region Private methods

            private byte[] EncryptGCM(byte[] input, AesEncryptionParameters aesParams) {
                if (aesParams.Key == null || aesParams.IV == null) throw new ArgumentException("Key and IV cannot be null.");
                if (aesParams.IV.Length != 12) throw new ArgumentException("For AES-GCM, IV (nonce) must be 12 bytes.");

                byte[] ciphertext = new byte[input.Length];
                byte[] tag = new byte[16];
                using (var aesGcm = new AesGcm(aesParams.Key.AsSpan(), 16)) {
                    aesGcm.Encrypt(aesParams.IV, input, ciphertext, tag, null);
                }

                byte[] result = new byte[aesParams.IV.Length + ciphertext.Length + tag.Length];
                Buffer.BlockCopy(aesParams.IV, 0, result, 0, aesParams.IV.Length);
                Buffer.BlockCopy(ciphertext, 0, result, aesParams.IV.Length, ciphertext.Length);
                Buffer.BlockCopy(tag, 0, result, aesParams.IV.Length + ciphertext.Length, tag.Length);

                CryptographicOperations.ZeroMemory(ciphertext);
                CryptographicOperations.ZeroMemory(tag);

                return result;
            }

            private byte[] DecryptGCM(byte[] input, AesEncryptionParameters aesParams) {
                if (input.Length < 12 + 16) throw new ArgumentException("Invalid input length for AES-GCM decryption.");

                int ciphertextLength = input.Length - 12 - 16;

                byte[] iv = new byte[12];
                byte[] ciphertext = new byte[ciphertextLength];
                byte[] tag = new byte[16];

                Buffer.BlockCopy(input, 0, iv, 0, 12);
                Buffer.BlockCopy(input, 12, ciphertext, 0, ciphertextLength);
                Buffer.BlockCopy(input, 12 + ciphertextLength, tag, 0, 16);

                byte[] decryptedData = new byte[ciphertextLength];
                using (var aesGcm = new AesGcm(aesParams.Key.AsSpan(), 16)) {
                    aesGcm.Decrypt(iv, ciphertext, tag, decryptedData, null);
                }

                CryptographicOperations.ZeroMemory(iv);
                CryptographicOperations.ZeroMemory(ciphertext);
                CryptographicOperations.ZeroMemory(tag);

                return decryptedData;
            }

        #endregion
    }
}
