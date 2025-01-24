using System.Security.Cryptography;
using System.Text;

namespace SimpleSecureData {
    public class SecureBytes : SecureData<byte[]> {
        #region Variables

            public int Length { get; private set; }

        #endregion

        #region Constructors

            public SecureBytes() {
                Length = 0;
            }

            public SecureBytes(byte[] data, bool destroyArray = false) : base() {
                Length = data.Length;

                SetBytes(data, destroyArray);
            }

            public SecureBytes(SecureBytes data) : base() {
                Length = data.Length;
                SetBytes(data.GetBytes(), true);
            }

        #endregion

        #region Public methods

            public void AppendData(SecureBytes data) {
                AppendData(data.GetBytes());
                Length += data.Length;
            }

            public override void SetBytes(byte[] newData, bool destroyArray = false) {
                Length = newData.Length;
                base.SetBytes(newData, destroyArray);   
            }

            public override void SetData(byte[] newData, bool destroyInput = false) {
                Length = newData.Length;
                base.SetData(newData, destroyInput);                
            }

            public override byte[] Serialize(byte[] input, bool destroyInput = false) {
                try {
                    return input;
                }
                finally {
                    if (destroyInput) DestroyType(ref input);
                }
            }

            public override byte[] Deserialize(byte[] input, bool destroyInput = false) {
                try {
                    return input;
                }
                finally {
                    if (destroyInput) CryptographicOperations.ZeroMemory(input);
                }
            }

            public override int GetLength() => Length;

            public override void DestroyType(ref byte[] input) {
                CryptographicOperations.ZeroMemory(input);
            }

            public override string ToString() {
                byte[] _b = GetBytes();

                try {
                    var sb = new StringBuilder();
                    foreach (var b in _b) sb.Append(b.ToString("x2"));


                    return sb.ToString();
                }
                finally {
                    CryptographicOperations.ZeroMemory(_b);
                }
            }

            public override int GetHashCode() {
                return base.GetHashCode();
            }

            public override bool Equals(object? obj) {
                if (obj == null) return false;
                if(!(obj is SecureBytes sb)) return false;

                if(Length != sb.Length) return false;

                byte[] _b = GetBytes();
                byte[] _sb = sb.GetBytes();

                try {
                    return _b.SequenceEqual(_sb);
                }
                finally {
                    CryptographicOperations.ZeroMemory(_b);
                    CryptographicOperations.ZeroMemory(_sb);
                }
            }

            public override void Dispose() {
                base.Dispose();
                Length = 0;
            }

        #endregion
    }
}
