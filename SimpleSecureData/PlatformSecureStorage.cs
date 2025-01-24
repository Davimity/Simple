using System.Collections.Concurrent;
using System.Security.Cryptography;

#if ANDROID
    using AndroidX.Security.Crypto;
#endif

#if IOS
    using Security;
#endif

namespace SimpleSecureData {
    public static class PlatformSecureStorage {
        #region Variables

            //For not available platforms, we use a dictionary to store the secrets
            private static readonly ConcurrentDictionary<Guid, byte[]> _fallbackStore = [];

            private static readonly byte[] _fallbackKey;
            private static readonly byte[] _fallbackHmacKey;

        #endregion

        #region Constructor

            static PlatformSecureStorage() {
                _fallbackKey = new byte[32];
                _fallbackHmacKey = new byte[32];

                RandomNumberGenerator.Fill(_fallbackKey);  
                RandomNumberGenerator.Fill(_fallbackHmacKey);
            }

        #endregion

        #region Public methods

            public static Guid StoreSecret(byte[] data) {
                if(data == null || data.Length == 0) throw new ArgumentNullException(nameof(data), "Data cannot be null or empty.");

                Guid secretId = Guid.NewGuid();

                switch (PlatformManager.CurrentPlatform) {
                    #if WINDOWS
                        case PlatformType.Windows:
                        
                            byte[] protectedData = ProtectedData.Protect(data, null, DataProtectionScope.CurrentUser);
                            _fallbackStore[secretId] = protectedData;
                            break;
                    #endif
                    #if ANDROID
                        case PlatformType.Android:
                            var context = Application.Context;
                            string mainKeyAlias = MasterKeys.GetOrCreate(MasterKeys.Aes256GcmSpec);

                            var prefs = EncryptedSharedPreferences.Create(
                                "MySecureDataPrefs",
                                mainKeyAlias,
                                context,
                                EncryptedSharedPreferences.PrefKeyEncryptionScheme.Aes256Siv,
                                EncryptedSharedPreferences.PrefValueEncryptionScheme.Aes256Gcm
                            );

                            string? base64 = null;
                            try {
                                base64 = Convert.ToBase64String(data);
                                string prefsKey = secretId.ToString();

                                var editor = prefs.Edit();
                                if(editor == null) throw new InvalidOperationException("Failed to create EncryptedSharedPreferences.Editor.");

                                editor.PutString(prefsKey, base64);
                                editor.Commit();
                            }
                            finally {
                                base64 = null;
                            }

                            break;
                    #endif
                    #if IOS
                        case PlatformType.iOS:
                            unsafe{
                                fixed(byte* pData = data){
                                    using var nsData = NSData.FromBytesNoCopy((IntPtr)pData, (nuint)data.Length, false);

                                    string account = secretId.ToString();
                                    var record = new SecRecord(SecKind.GenericPassword){
                                        Service = "PlatformSecureStorage",
                                        Account = account,
                                        ValueData = nsData,
                                        Accessible = SecAccessible.WhenUnlockedThisDeviceOnly
                                    };

                                    var res = SecKeyChain.Add(record);
                                    if (res != SecStatusCode.Success)
                                        throw new CryptographicException($"Error storing data in iOS Keychain: {res}");
                                }
                            }
                            break;
                    #endif
                    default:
                        byte[] iv = new byte[16];
                        RandomNumberGenerator.Fill(iv);

                        byte[] ciphertext = SimpleEncryption.Encryption.Aes.Encrypt(
                            input: data,
                            key: _fallbackKey,
                            iv: iv
                        );

                        byte[] combined = new byte[16 + ciphertext.Length];

                        Buffer.BlockCopy(iv, 0, combined, 0, 16);
                        Buffer.BlockCopy(ciphertext, 0, combined, 16, ciphertext.Length);

                        byte[] hmac;
                        using (var hmacSha = new HMACSHA256(_fallbackHmacKey)) {
                            hmac = hmacSha.ComputeHash(combined);
                        }

                        byte[] final = new byte[combined.Length + 32];

                        Buffer.BlockCopy(combined, 0, final, 0, combined.Length);
                        Buffer.BlockCopy(hmac, 0, final, combined.Length, 32);

                        _fallbackStore[secretId] = final;
                        break;
                }

                return secretId;
            }

            public static byte[]? RetrieveSecret(Guid id) {
                switch (PlatformManager.CurrentPlatform) {
                    #if WINDOWS
                        case PlatformType.Windows:
                            if(!_fallbackStore.TryGetValue(id, out var protectedData)) return null;
                            try{
                                return ProtectedData.Unprotect(protectedData, null, DataProtectionScope.CurrentUser);
                            }catch{
                                return null;
                            }
                    #endif
                    #if ANDROID
                        case PlatformType.Android:
                            var context = Application.Context;
                            string mainKeyAlias = MasterKeys.GetOrCreate(MasterKeys.Aes256GcmSpec);
                        
                            var prefs = EncryptedSharedPreferences.Create(
                                "MySecureDataPrefs",
                                mainKeyAlias,
                                context,
                                EncryptedSharedPreferences.PrefKeyEncryptionScheme.Aes256Siv,
                                EncryptedSharedPreferences.PrefValueEncryptionScheme.Aes256Gcm
                            );

                            string? base64 = prefs.GetString(id.ToString(), null);
                            if (base64 == null) return null;

                            try {
                                byte[] data = Convert.FromBase64String(base64);
                                base64 = null;
                                return data;
                            }
                            catch {
                                base64 = null;
                                return null;                              
                            }
                    #endif
                    #if IOS
                        case PlatformType.iOS:
                            string account = id.ToString();
                            var query = new SecRecord(SecKind.GenericPassword) {
                                Service = "PlatformSecureStorage",
                                Account = account,
                            };

                            SecStatusCode res;
                            var match = SecKeyChain.QueryAsRecord(query, out res);
                            if(res == SecStatusCode.Success && match?.ValueData != null) return match.ValueData.ToArray();
                            return null;
                    #endif
                    default:
                        if (!_fallbackStore.TryGetValue(id, out var final)) return null;

                        if (final.Length < 16 + 32) return null;

                        int minLen = 16 + 32;
                        int ciphertextLen = final.Length - minLen;
                        if (ciphertextLen <= 0) return null;

                        byte[] ivCiphertext = new byte[16 + ciphertextLen];
                        Buffer.BlockCopy(final, 0, ivCiphertext, 0, ivCiphertext.Length);

                        byte[] storedHmac = new byte[32];
                        Buffer.BlockCopy(final, ivCiphertext.Length, storedHmac, 0, 32);

                        byte[] computedHmac;
                        using (var hmacSha = new HMACSHA256(_fallbackHmacKey)) {
                            computedHmac = hmacSha.ComputeHash(ivCiphertext);
                        }

                        if (!CryptographicOperations.FixedTimeEquals(storedHmac, computedHmac)) return null;

                        byte[] iv = new byte[16];
                        Buffer.BlockCopy(ivCiphertext, 0, iv, 0, 16);
                        int actualCipherLen = ivCiphertext.Length - 16;
                        byte[] ciphertext = new byte[actualCipherLen];
                        Buffer.BlockCopy(ivCiphertext, 16, ciphertext, 0, actualCipherLen);

                        try {
                            byte[] plain = SimpleEncryption.Encryption.Aes.Decrypt(ciphertext, _fallbackKey, iv);
                            return plain;
                        }
                        catch {
                            return null;
                        }
                }
            }

            public static void RemoveSecret(Guid id) {
                switch (PlatformManager.CurrentPlatform) {
                    #if WINDOWS
                        case PlatformType.Windows:
                            if (_fallbackStore.TryRemove(id, out var protectedData)) {
                                CryptographicOperations.ZeroMemory(protectedData);
                            }
                            return;
                    #endif
                    #if ANDROID
                        case PlatformType.Android:
                            var context = Application.Context;
                            string mainKeyAlias = MasterKeys.GetOrCreate(MasterKeys.Aes256GcmSpec);

                            var prefs = EncryptedSharedPreferences.Create(
                                "MySecureDataPrefs",
                                mainKeyAlias,
                                context,
                                EncryptedSharedPreferences.PrefKeyEncryptionScheme.Aes256Siv,
                                EncryptedSharedPreferences.PrefValueEncryptionScheme.Aes256Gcm
                            );

                            string prefsKey = id.ToString();
                            if (prefs.Contains(prefsKey)) {
                                var editor = prefs.Edit();
                                if(editor == null) throw new InvalidOperationException("Failed to create EncryptedSharedPreferences.Editor.");
                                editor.Remove(prefsKey);
                                editor.Commit();
                            }
                            return;
                    #endif
                    #if IOS
                        case PlatformType.iOS:
                            string account = id.ToString();
                            var record = new SecRecord(SecKind.GenericPassword){
                                Service = "PlatformSecureStorage",
                                Account = account
                            };
                            SecKeyChain.Remove(record);
                            return;
                    #endif
                    default:
                        if (_fallbackStore.TryRemove(id, out var final)) {
                            CryptographicOperations.ZeroMemory(final);
                        }
                        break;
                }
            }
        
        #endregion
    }
}
