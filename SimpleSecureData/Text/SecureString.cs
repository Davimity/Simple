using System.Security.Cryptography;
using System.Text;

namespace SimpleSecureData.Text {
    public class SecureString : SecureData<char[]> {
        #region Variables

            public Encoding Encoding { get; set; }

            public int Length { get; private set; }

        #endregion

        #region Constructors

            public SecureString(byte[]? additionalData) : base(additionalData) {
                Encoding = Encoding.UTF8;
                Length = 0;
            }

            public SecureString(char[] data, bool destroyArray = false, byte[]? additionalData = null) : base(data, destroyArray, additionalData) {
                Encoding = Encoding.UTF8;
                Length = data.Length;
            }

            public SecureString(char[] data, Encoding encoding, bool destroyArray = false, byte[]? additionalData = null) : base(data, destroyArray, additionalData) {
                Encoding = encoding;
                Length = data.Length;
            }

            public SecureString(string data, byte[]? additionalData = null) : base(additionalData) {
                Encoding = Encoding.UTF8;
                Length = data.Length;

                SetData(data.ToCharArray(), true);
            }

            public SecureString(string data, Encoding encoding, byte[]? additionalData = null) : base(additionalData) {
                Encoding = encoding;
                Length = data.Length;

                SetData(data.ToCharArray(), true);
            }

            public SecureString(byte[] data, bool destroyArray = false, byte[]? additionalData = null) : base(data, destroyArray, additionalData) {
                Encoding = Encoding.UTF8;
                Length = data.Length;
            }

            public SecureString(byte[] data, Encoding encoding, bool destroyArray = false, byte[]? additionalData = null) : base(data, destroyArray, additionalData) {
                Encoding = encoding;
                Length = data.Length / encoding.GetByteCount(" ");
            }

            public SecureString(SecureBytes data, byte[]? additionalData = null) : base(additionalData) {
                Encoding = Encoding.UTF8;
                Length = data.Length;

                SetBytes(data.GetBytes(), true);
            }

            public SecureString(SecureBytes data, Encoding encoding, byte[]? additionalData = null) : base(additionalData) {
                Encoding = encoding;
                Length = data.Length / encoding.GetByteCount(" ");

                SetBytes(data.GetBytes(), true);
            }

            public SecureString(SecureString data, byte[]? additionalData = null) : base(additionalData) {
                Encoding = data.Encoding;
                Length = data.Length;
                SetData(data.GetData(), true);
            }

        #endregion

        #region Public methods

            /// <summary> Append a string to the SecureString object. </summary>
            /// <param name="data"> The string to append. </param>
            public void AppendData(string data) {
                AppendData(Encoding.GetBytes(data));
                Length += data.Length;
            }

            /// <summary> Append a SecureString object to the SecureString object. </summary>
            /// <param name="data"> The SecureString object to append. </param>
            public void AppendData(SecureString data) {
                AppendData(data.GetData());
                Length += data.Length;
            }

            /// <summary> Set the data of the SecureString object. </summary>
            /// <param name="newData"> The new data to set. </param>
            /// <param name="destroyArray"> Whether to destroy the array after setting the data. </param>
            public override void SetBytes(byte[] newData, bool destroyArray = false) {
                Length = Encoding.GetCharCount(newData);
                base.SetBytes(newData, destroyArray);         
            }

            /// <summary> Set the data of the SecureString object. </summary>
            /// <param name="newData"> The new data to set. </param>
            /// <param name="destroyInput"> Whether to destroy the input after setting the data. </param>
            public override void SetData(char[] newData, bool destroyInput = false) {
                Length = newData.Length;
                base.SetData(newData, destroyInput);  
            }

            /// <summary> Obtain a substring of the SecureString object. </summary>
            /// <param name="start"> The start index of the substring. </param>
            /// <param name="length"> The length of the substring. </param>
            /// <returns> The substring of the SecureString object. </returns>
            SecureString Substring(int start, int length) {
                var result = new char[length];
                Array.Copy(GetData(), start, result, 0, length);

                return new SecureString(result, Encoding, true);
            }

            /// <summary> Obtain a substring of the SecureString object. </summary>
            /// <param name="start"> The start index of the substring. </param>
            /// <returns> The substring of the SecureString object from the start index to the end. </returns>
            public SecureString Substring(int start) {
                var result = new char[Length - start];
                Array.Copy(GetData(), start, result, 0, result.Length);

                return new SecureString(result, Encoding, true);
            }

            /// <summary> Obtain the index of the first occurrence of a character in the SecureString object. </summary>
            /// <param name="c"> The character to find. </param>
            /// <returns> The index of the first occurrence of the character. </returns>
            public int IndexOf(char c) {
                var result = GetData();

                for (var i = 0; i < result.Length; i++) {
                    if (result[i] == c) {
                        Array.Fill(result, '\0');
                        return i;
                    }
                    
                    result[i] = '\0';
                }

                return -1;
            }

            /// <summary> Obtain the index of the first occurrence of a string in the SecureString object. </summary>
            /// <param name="s"> The string to find. </param>
            /// <returns> The index of the first occurrence of the string. </returns>
            public int IndexOf(string s) {
                var result = GetData();
                var actual = 0;

                for (var i = 0; i < result.Length; i++) {
                    if (result[i] != s[actual++]) actual = 0;
                    else if (actual == s.Length) {
                        Array.Fill(result, '\0');
                        return i - actual + 1;
                    }
                    
                    result[i] = '\0';
                }

                return -1;
            }

            /// <summary> Split the SecureString object by a character. </summary>
            /// <param name="c"> The character to split by. </param>
            /// <returns> The SecureString objects split by the character. </returns>
            public SecureString[] Split(params char[] c) {
                var result = GetData();

                var list = new List<SecureString>();
                var start = 0;

                for (var i = 0; i < result.Length; i++) {
                    if (c.Contains(result[i])) {
                        int tmp = i - start;

                        list.Add(Substring(start, tmp));
                        Array.Fill(result, '\0', start, tmp);

                        start = i + 1;                   
                    }
                }

                list.Add(Substring(start));
                Array.Fill(result, '\0');
                return list.ToArray();
            }

            /// <summary> Serialize the SecureString into a byte array. </summary>
            /// <param name="input"> The input to serialize. </param>
            /// <param name="destroyInput"> Whether to destroy the input after serialization. </param>
            /// <returns> The serialized input. </returns>
            public override byte[] Serialize(char[] input, bool destroyInput = false) {
                try {
                    return Encoding.GetBytes(input);
                }
                finally {
                    if (destroyInput) DestroyType(ref input);
                }
            }

            /// <summary> Deserialize the SecureString from a byte array. </summary>
            /// <param name="input"> The input to deserialize. </param>
            /// <param name="destroyInput"> Whether to destroy the input after deserialization. </param>
            /// <returns> The deserialized input. </returns>
            public override char[] Deserialize(byte[] input, bool destroyInput = false) {
                try {
                    return Encoding.GetChars(input);
                }
                finally {
                    if (destroyInput) CryptographicOperations.ZeroMemory(input);
                }
            }

            /// <summary> Destroy the SecureString object. </summary>
            /// <param name="input"> The SecureString object to destroy. </param>
            public override void DestroyType(ref char[] input) {
                for (var i = 0; i < input.Length; i++) input[i] = '\0';
            }

            /// <summary> Obtain the string representation of the SecureString object. </summary>
            /// <returns> The SecureString object as a string. </returns>
            public override string ToString() => new(GetData());

            /// <summary> Dispose the SecureString object. </summary>
            public override void Dispose() {
                base.Dispose();
                Length = 0;
            }

        #endregion
    }
}
