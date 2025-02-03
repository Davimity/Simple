using System.Security.Cryptography;
using System.Text;

namespace SimpleEncryption.Derivation {
    ///<summary> Class for the PBKDF2 key derivation algorithm </summary>
    ///<remarks> For empty or null input, the result will be an empty string or byte array. </remarks>
    public static class Pbkdf2 {
        #region Variables

            private static readonly Pbkdf2Algorithm _algorithm = new();

        #endregion

        #region Public methods

            /// <summary> Derives a key from a input string using the specified parameters </summary>
            /// <param name="input"> The input to derive the key from </param>
            /// <param name="parameters"> Parameters to use </param>
            /// <returns> Derived key </returns>
            public static string DeriveKey(string? input, Pbkdf2Parameters parameters) {
                if (string.IsNullOrEmpty(input)) return string.Empty;

                byte[] inputBytes = Encoding.UTF8.GetBytes(input);
                byte[] result = _algorithm.DeriveKey(inputBytes, parameters);

                string sresult = Convert.ToBase64String(result);

                CryptographicOperations.ZeroMemory(inputBytes);
                CryptographicOperations.ZeroMemory(result);

                return sresult;
            }

            /// <summary> Derives a key from a input string using the specified parameters </summary>
            /// <param name="input"> The input to derive the key from </param>
            /// <param name="salt"> Salt to use </param>
            /// <param name="keySize"> Length of the key in bytes </param>
            /// <param name="iterations"> Number of iterations to use </param>
            /// <param name="hashAlgorithm"> Hash algorithm to use </param>
            /// <returns> Derived key </returns>
            public static string DeriveKey(string? input, byte[]? salt = null, int keySize = 32, int iterations = 100000, HashAlgorithmName hashAlgorithm = default) {
                if (string.IsNullOrEmpty(input)) return string.Empty;
                if (hashAlgorithm == default) hashAlgorithm = HashAlgorithmName.SHA256;
                if (salt == null) salt = Array.Empty<byte>();

                return DeriveKey(input, new Pbkdf2Parameters() { KeySize = keySize, Iterations = iterations, Salt = salt, HashAlgorithm = hashAlgorithm });
            }

            /// <summary> Derives a key from a password and a salt </summary>
            /// <param name="input"> Password to derive the key from </param>
            /// <param name="parameters"> Parameters to use </param>
            /// <returns> Derived key </returns>
            public static byte[] DeriveKey(byte[]? input, Pbkdf2Parameters parameters) => _algorithm.DeriveKey(input, parameters);

            /// <summary> Derives a key from bytes using the specified parameters </summary>
            /// <param name="input"> Password to derive the key from </param>
            /// <param name="salt"> Salt to use </param>
            /// <param name="keySize"> Length of the key in bytes </param>
            /// <param name="iterations"> Number of iterations to use </param>
            /// <param name="hashAlgorithm"> Hash algorithm to use. (SHA256, SHA386, SHA512...) </param>
            /// <returns> Derived key. </returns>
            public static byte[] DeriveKey(byte[]? input, byte[]? salt = null, int keySize = 32, int iterations = 100000, HashAlgorithmName hashAlgorithm = default) {
                if(input == null || input.Length == 0) return Array.Empty<byte>();
                if (hashAlgorithm == default) hashAlgorithm = HashAlgorithmName.SHA256;
                if (salt == null) salt = Array.Empty<byte>();

                return _algorithm.DeriveKey(input, new Pbkdf2Parameters() { KeySize = keySize, Iterations = iterations, Salt = salt, HashAlgorithm = hashAlgorithm });
            }

        #endregion
    }

    ///<summary> Parameters for the PBKDF2 key derivation algorithm, checks if key size and iterations are greater than 0 and if new value of salt is not null or empty. </summary>
    ///<remarks> Initially, the salt is an empty byte array. Use the dispose method to clear the data (key size and iterations will be set to 0 and salt to empty array after cleaning content from memory). Default key size is 32 and iterations 100000 </remarks>
    public class Pbkdf2Parameters : KeyDerivationParameters {
        #region Variables

            private int _keySize = 32;
            private int _iterations = 100000;
            
            private byte[] _salt = Array.Empty<byte>();

        #endregion

        #region Properties

            /// <summary> The hash algorithm to use. </summary>
            public HashAlgorithmName HashAlgorithm = HashAlgorithmName.SHA256;

            /// <summary> The size of the derived key in bytes. </summary>
            public int KeySize {
                get => _keySize;
                set => _keySize = value > 0 ? value : throw new Exception("Key size must be greater than 0.");
            }

            /// <summary> The number of iterations to use. </summary>
            public int Iterations {
                get => _iterations;
                set => _iterations = value > 0 ? value : throw new Exception("Iterations must be greater than 0.");
            }

            /// <summary> The salt to use. </summary>
            public byte[] Salt {
                get => _salt;
                set => _salt = value != null ? (byte[])value.Clone() : throw new ArgumentException("Salt must not be null or empty.", nameof(value));
            }

        #endregion

        #region Public methods

            public override void Dispose() {
                _keySize = 0;
                _iterations = 0;

                if (_salt != null && _salt.Length > 0) {
                    CryptographicOperations.ZeroMemory(_salt);
                    _salt = Array.Empty<byte>();
                }
            }

        #endregion
    }

    ///<summary> Implementation of the PBKDF2 key derivation algorithm </summary>
    ///<remarks> For empty or null input, the result will be an empty byte array. </remarks>
    public class Pbkdf2Algorithm : IKeyDerivationAlgorithm {
        /// <summary> Derives a key from the input using the specified parameters. </summary>
        /// <param name="input"> The input to derive the key from. </param>
        /// <param name="parameters"> Parameters to use. </param>
        /// <returns> Derived key. </returns>
        ///<remarks> Always use salt with length greater than 0 for better security </remarks>
        public byte[] DeriveKey(byte[]? input, KeyDerivationParameters parameters) {
            if (input == null || input.Length == 0) return Array.Empty<byte>();
            if (parameters is not Pbkdf2Parameters pbkdf2Parameters) throw new ArgumentException("Parameters must be of type Pbkdf2Parameters.");

            using var pbkdf2 = new Rfc2898DeriveBytes(input, pbkdf2Parameters.Salt, pbkdf2Parameters.Iterations, pbkdf2Parameters.HashAlgorithm);
            return pbkdf2.GetBytes(pbkdf2Parameters.KeySize);
        }
    }
}
