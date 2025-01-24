using SimpleEncryption.Hashing;
using System.Security.Cryptography;

namespace SimpleSecureData {
    internal sealed class SecureKey {
        #region Variables

            private readonly Guid _secretId;
            private readonly int _keySize;

            private bool _disposed;      

        #endregion

        #region Properties

            public int KeySize => _keySize;
            public bool Disposed => _disposed;

            public byte[] Key {
                get {
                    byte[]? retrieved = PlatformSecureStorage.RetrieveSecret(_secretId);
                    if (retrieved == null || retrieved.Length != _keySize)
                        throw new InvalidOperationException("Failed to retrieve the key from platform or invalid size.");

                    return retrieved;
                }
            }

        #endregion

        #region Constructors

            public SecureKey(int keySize = 32) {
                if(keySize <= 0) keySize = 32;
                _keySize = keySize;

                byte[] ephemeral = new byte[_keySize];
                RandomNumberGenerator.Fill(ephemeral);

                try {
                    _secretId = PlatformSecureStorage.StoreSecret(ephemeral);
                }
                finally {
                    CryptographicOperations.ZeroMemory(ephemeral);
                }
            }

        #endregion

        #region Public methods

            public byte[] GetKey() {
                byte[]? retrieved = PlatformSecureStorage.RetrieveSecret(_secretId);
                if (retrieved == null || retrieved.Length != _keySize)
                    throw new InvalidOperationException("Failed to retrieve the key from platform or invalid size.");

                return retrieved;
            }

            ///<summary> Gets the ID of the secret. </summary>
            ///<returns> The ID of the secret. </returns>
            public byte[] GetId() {
                return Sha256.Hash(_secretId.ToByteArray(), BitConverter.GetBytes(_secretId.GetHashCode()));
            }

            /// <summary> Disposes the object. </summary>
            public void Dispose() {
                if (_disposed) return;
                PlatformSecureStorage.RemoveSecret(_secretId);
                _disposed = true;
            }

            /// <summary> Checks if the object is equal to another object. </summary>
            /// <returns> Whether the object is equal to another object. </returns>
            public override int GetHashCode() {
                return _secretId.GetHashCode();
            }

        #endregion
    }
}
