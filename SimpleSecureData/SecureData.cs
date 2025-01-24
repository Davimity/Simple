using System.Security.Cryptography;
using SimpleEncryption.Encryption;
using SimpleSecureData;

namespace SimpleSecureData {
    public abstract class SecureData<T> : IDisposable{
        #region Variables

            private readonly SecureKey _secureKey;
            private Memory<byte> _data;

            private readonly byte[] _aad;

            private bool _disposed;

        #endregion

        #region Constructors

            protected SecureData(byte[]? additionalData = null) {          
                _secureKey = new SecureKey();
                _aad = additionalData ?? Array.Empty<byte>();
                _data = Array.Empty<byte>();
            }

            protected SecureData(byte[] data, bool destroyArray = false, byte[]? additionalData = null) : this(additionalData) {
                SetBytes(data, destroyArray);
            }

            protected SecureData(T data, bool destroyInput = false, byte[]? additionalData = null) : this(additionalData) {
                SetData(data, destroyInput);
            }

        #endregion

        #region Public methods

            /// <summary> Sets the data of the SecureData object. </summary>
            /// <param name="newData"> The new data to set. </param>
            /// <param name="destroyArray"> Whether to destroy the array after setting the data. </param>
            /// <remarks> Safer than SetData with T for some types like strings that are immutable. </remarks>
            public virtual void SetBytes(byte[] newData, bool destroyArray = false) {
                if(_disposed) throw new ObjectDisposedException(nameof(SecureData<T>));

                byte[] k = _secureKey.Key;
                byte[] encData;

                unsafe {
                    fixed (byte* _ = k) {
                        encData = ChaCha20.Encrypt(newData, k, ChaCha20.GenerateNonce(), CalculateAAD());
                        CryptographicOperations.ZeroMemory(k);
                    }
                }

                if (destroyArray) CryptographicOperations.ZeroMemory(newData);
  
                _data = new Memory<byte>(encData);
            }

            /// <summary> Sets the data of the SecureData object. </summary>
            /// <param name="newData"> The new data to set. </param>
            /// <param name="destroyInput"> Whether to destroy the input after setting the data. </param>
            public virtual void SetData(T newData, bool destroyInput = false) {
                SetBytes(Serialize(newData), true);
                if (destroyInput) DestroyType(ref newData);
            }

            /// <summary> Appends data to the SecureData object. </summary>
            /// <param name="newData"> The new data to append. </param>
            /// <param name="destroyArray"> Whether to destroy the array after appending the data. </param>
            public void AppendData(byte[] newData, bool destroyArray = false) {
                byte[] encData;
                byte[] finalData;

                var actualData = new byte[_data.Length];
                _data.Span.CopyTo(actualData);

                byte[] k = _secureKey.Key;

                unsafe {
                    fixed (byte* _ = k) {

                        var decData = ChaCha20.Decrypt(actualData, k, CalculateAAD());

                        fixed (byte* __ = decData) {

                            finalData = new byte[decData.Length + newData.Length];

                            fixed (byte* ___ = finalData) {
                                Array.Copy(decData, 0, finalData, 0, decData.Length);
                                Array.Copy(newData, 0, finalData, decData.Length, newData.Length);

                                CryptographicOperations.ZeroMemory(decData);

                                encData = ChaCha20.Encrypt(finalData, k, ChaCha20.GenerateNonce(), CalculateAAD());

                                CryptographicOperations.ZeroMemory(k);
                                CryptographicOperations.ZeroMemory(finalData);
                            }
                        }
                    }
                }

                CryptographicOperations.ZeroMemory(actualData);

                if (destroyArray) CryptographicOperations.ZeroMemory(newData);

                _data = new Memory<byte>(encData);
            }

            /// <summary> Appends data to the SecureData object. </summary>
            /// <param name="newData"> The new data to append. </param>
            /// <param name="destroyInput"> Whether to destroy the input after appending the data. </param>
            public void AppendData(T newData, bool destroyInput = false) {
                AppendData(Serialize(newData), true);
                if (destroyInput) DestroyType(ref newData);
            }

            /// <summary> Gets the data bytes of the SecureData object. </summary>
            /// <returns> The data bytes of the SecureData object. </returns>
            public byte[] GetBytes() {
                var result = new byte[_data.Length];
                _data.Span.CopyTo(result);

                byte[] k = _secureKey.Key;
                byte[] decResult;

                unsafe {
                    fixed(byte* _ = k) {
                        decResult = ChaCha20.Decrypt(result, k, CalculateAAD());

                        CryptographicOperations.ZeroMemory(k);
                        CryptographicOperations.ZeroMemory(result);
                    }
                }

                return decResult;
            }

            /// <summary> Gets the data of the SecureData object. </summary>
            /// <returns> The data of the SecureData object. </returns>
            /// <remarks> May not be safe to use with types like strings that are immutable. </remarks>
            public T GetData() {
                var b = GetBytes();

                T? result;

                unsafe {
                    fixed (byte* _ = b) {
                        result = Deserialize(b);
                        CryptographicOperations.ZeroMemory(b);
                    }            
                }

                return result;
            }

            /// <summary> Destroys the data of the SecureData object. </summary>
            /// <returns> The data of the SecureData object. </returns>
            public virtual int GetLength() => _data.Length;

            /// <summary> Disposes the SecureData object. </summary>
            public virtual void Dispose() {
                _secureKey.Dispose();
                _data.Span.Clear();
            }

            /// <summary> Gets the hash code of the SecureData object. </summary>
            /// <returns> The hash code of the SecureData object. </returns>
            public override int GetHashCode() {
                int b = _secureKey.GetHashCode();
                int h = 0;

                for (var i = 0; i < _data.Length; i++) 
                    h = h * 31 + _data.Length - i;
                  
                return h;
            }

            /// <summary> Checks if the SecureData object is equal to another object. </summary>
            /// <param name="obj"> The object to compare to. </param>
            /// <returns> Whether the SecureData object is equal to the other object. </returns>
            public override bool Equals(object? obj) {
                if(obj == null || GetType() != obj.GetType()) return false;

                SecureData<T> sobj = (SecureData<T>)obj;

                bool equals;

                unsafe {
                    byte[] b = GetBytes();
                
                    fixed(byte* _ = b) {

                        byte[] ob = sobj.GetBytes();

                        fixed(byte* __ = ob) {

                            equals = b.Length == ob.Length && b.SequenceEqual(ob);

                            CryptographicOperations.ZeroMemory(b);
                            CryptographicOperations.ZeroMemory(ob);
                        }
                    }
                }

                return equals;
            }

            /// <summary> Gets the byte representation of the SecureData object. </summary>
            /// <param name="input"> The SecureData object to get the byte representation of. </param>
            /// <param name="destroyInput"> Whether to destroy the input after getting the byte representation. </param>
            /// <returns> The byte representation of the SecureData object. </returns>
            public abstract byte[] Serialize(T input, bool destroyInput = false);

            /// <summary> Gets the SecureData object from the byte representation. </summary>
            /// <param name="input"> The byte representation of the SecureData object. </param>
            /// <param name="destroyArray"> Whether to destroy the array after getting the SecureData object. </param>
            /// <returns> The SecureData object from the byte representation. </returns>
            public abstract T Deserialize(byte[] input, bool destroyArray = false);

            /// <summary> Destroys the SecureData object. </summary>
            /// <param name="input"> The SecureData object to destroy. </param>
            public abstract void DestroyType(ref T input);

        #endregion

        #region Private methods

            private byte[] CalculateAAD() {
                byte[] skk = _secureKey.GetId();
                byte[] bytes = new byte[skk.Length + _aad.Length];

                Array.Copy(skk, 0, bytes, 0, skk.Length);
                Array.Copy(_aad, 0, bytes, skk.Length, _aad.Length);

                CryptographicOperations.ZeroMemory(skk);

                return bytes;
            }

        #endregion
    }
}
