using System.Security.Cryptography;
using System.Text;

namespace SimpleSecureData.Text {
    public class SecureChar : SecureData<char> {

        #region Variables

            public Encoding Encoding { get; set; }

        #endregion

        #region Constructors

            public SecureChar(byte[]? additionalData = null) : base(additionalData) {
                Encoding = Encoding.UTF8;
            }

            public SecureChar(char data, byte[]? additionalData = null) : base(data, false, additionalData) {
                Encoding = Encoding.UTF8;
            }

            public SecureChar(byte[] data, bool destroyArray = false, byte[]? additionalData = null) : base(data, destroyArray, additionalData) {
                Encoding = Encoding.UTF8;
            }

            public SecureChar(byte[] data, Encoding encoding, bool destroyArray = false, byte[]? additionalData = null) : base(data, destroyArray, additionalData) {
                Encoding = encoding;
            }

        #endregion

        #region Public methods

            /// <summary> Transforms the input into a byte array. </summary>
            /// <param name="input"> The input to serialize. </param>
            /// <param name="destroyInput"> Whether to destroy the input after serialization. </param>
            /// <returns> The serialized input. </returns>
            public override byte[] Serialize(char input, bool destroyInput = false) {
                try {
                    return Encoding.GetBytes(input.ToString());
                }
                finally {
                    if(destroyInput) DestroyType(ref input);
                }
            }

            /// <summary> Transforms the input into a char. </summary>
            /// <param name="input"> The input to deserialize. </param>
            /// <param name="destroyInput"> Whether to destroy the input after deserialization. </param>
            public override char Deserialize(byte[] input, bool destroyInput = false) {
                try {
                    return Encoding.GetChars(input)[0];
                }
                finally {
                    if (destroyInput) CryptographicOperations.ZeroMemory(input);
                }
            }

            /// <summary> Destroys the input. </summary>
            /// <param name="input"> The input to destroy. </param>
            public override void DestroyType(ref char input) {
                input = '\0';
            }

            ///<summary> Transforms the SecureChar object into a string. </summary>
            ///<returns> The SecureChar object as a string. </returns>
            public override string ToString() => GetData().ToString();

        #endregion
    }
}
