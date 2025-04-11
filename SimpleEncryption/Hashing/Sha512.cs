using SimpleEncryption.Derivation;
using System.Security.Cryptography;
using System.Text;

namespace SimpleEncryption.Hashing {
    ///<summary> Class for the Sha512 hashing algorithm </summary>
    ///<remarks> For null input, an exception will be thrown. </remarks>
    public class Sha512 {
        #region Variables

            private static readonly Sha512Algorithm _algorithm = new();

        #endregion

        #region Public Methods

            ///<summary> Hashes a string using SHA512 hashing </summary>
            ///<param name="input"> The string to hash </param>
            ///<param name="parameters"> The parameters to use </param>
            ///<returns> The hashed string </returns>
            public static string Hash(string input, Sha512HashParameters parameters) {
                if (input == null) throw new ArgumentNullException(nameof(input));

                byte[] inputBytes = Encoding.UTF8.GetBytes(input);
                var data = _algorithm.Hash(inputBytes, parameters);

                CryptographicOperations.ZeroMemory(inputBytes);

                var sb = new StringBuilder();
                foreach (var b in data) sb.Append(b.ToString("x2"));

                CryptographicOperations.ZeroMemory(data);

                return sb.ToString();
            }

            ///<summary> Hashes a string using SHA512 hashing </summary>
            ///<param name="input"> The string to hash </param>
            ///<param name="salt"> The salt to add </param>
            ///<returns> The hashed string </returns>
            public static string Hash(string input, string? salt = null) => Hash(input, new Sha512HashParameters { Salt = salt == null ? null : Encoding.UTF8.GetBytes(salt) });

            ///<summary> Hashes a byte array using SHA512 hashing </summary>
            ///<param name="input"> The byte array to hash </param>
            ///<param name="parameters"> The parameters to use </param>
            ///<returns> The hashed byte array </returns>
            public static byte[] Hash(byte[] input, Sha512HashParameters parameters) => _algorithm.Hash(input, parameters);

            ///<summary> Hashes a byte array using SHA512 hashing </summary>
            ///<param name="input"> The byte array to hash </param>
            ///<param name="salt"> The salt to add </param>
            ///<returns> The hashed byte array </returns>
            public static byte[] Hash(byte[] input, byte[]? salt = null) => Hash(input, new Sha512HashParameters { Salt = salt });

        #endregion
    }

    ///<summary> Parameters for the Sha512 hashing algorithm </summary>
    ///<remarks> Initially, salt is null. Use the dispose method to clear the data (salt will be set to null). </remarks>
    public class Sha512HashParameters : HashParameters {
        #region Variables

            private byte[]? _salt;
            private int hmacIterations = 100000;
            private int hmacDerivedKeyLength = 128;

        #endregion

        #region Properties

            /// <summary> The salt to use. </summary>
            public byte[]? Salt {
                get => _salt;
                set {
                    _salt = value;
                }
            }

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

            /// <summary> The HMAC key to use. </summary>
            /// <remarks> This is not used in GCM mode. If null, default hmac key will be used (not recommended). </remarks>
            public byte[]? HmacKey = null;

            /// <summary> The salt to use for HMAC. </summary>
            /// <remarks> This is not used in GCM mode. If null, default hmac salt will be used. </remarks>
            public byte[]? HmacSalt = null;

            /// <summary> The length of the derived key in bytes. </summary>
            public int HmacDerivedKeyLength {
                get => hmacDerivedKeyLength;
                set {
                    if (value <= 0) throw new ArgumentException("HMAC derived key length must be greater than 0.");
                    hmacDerivedKeyLength = value;
                }
            }

        #endregion

        #region Public methods

            public override void Dispose() {
                if (_salt != null) {
                    CryptographicOperations.ZeroMemory(_salt);
                    _salt = null;
                }
            }

        #endregion
    }

    ///<summary> Implementation of the Sha512 hashing algorithm </summary>
    ///<remarks> For null input, an exception will be thrown. </remarks>
    public class Sha512Algorithm : IHashAlgorithm, IDisposable {
        #region Variables

            private readonly SHA512 _Sha = SHA512.Create();

        #endregion

        #region Public methods

            public byte[] Hash(byte[] input, HashParameters parameters) {
                if (input == null) throw new ArgumentNullException(nameof(input));
                if (parameters is not Sha512HashParameters sha512Params) throw new ArgumentException("Parameters must be of type Sha512HashParameters.");

                var combined = new byte[input.Length + (sha512Params.Salt == null ? 0 : sha512Params.Salt.Length)];

                Buffer.BlockCopy(input, 0, combined, 0, input.Length);
                if (sha512Params.Salt != null) Buffer.BlockCopy(sha512Params.Salt, 0, combined, input.Length, sha512Params.Salt.Length);

                byte[] result;

                if (sha512Params.UseHmac) {
                    if(sha512Params.HmacKey == null) throw new ArgumentNullException("If using HMAC, you must introduce HmacKey.");

                    byte[] derivedHmacKey = Pbkdf2.DeriveKey(sha512Params.HmacKey, sha512Params.HmacSalt ?? Encoding.UTF8.GetBytes("AES-HMAC"), sha512Params.HmacDerivedKeyLength, sha512Params.HmacIterations, sha512Params.HmacHashAlgorithm);
                    
                    using (var hmac = new HMACSHA512(derivedHmacKey)) {
                        result = hmac.ComputeHash(combined);
                    }

                    CryptographicOperations.ZeroMemory(derivedHmacKey);
                }
                else {
                    result = _Sha.ComputeHash(combined);
                }


                CryptographicOperations.ZeroMemory(combined);
                
                return result;
            }

            public void Dispose() {
                _Sha.Dispose();
            }

        #endregion
    }
}