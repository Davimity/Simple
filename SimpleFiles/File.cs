using System.Security.Cryptography;
using System.Text;

using SimpleEncryption.Encryption;

using Aes = SimpleEncryption.Encryption.Aes;

namespace SimpleFiles {
    public static class File{
        public enum EncryptionAlgorithm {
            Aes,
            ChaCha20
        }

        ///<summary> Reads a file </summary>
        ///<param name="filePath"> The path to the file </param>
        ///<param name="linesToRead"> The lines to read </param>
        ///<param name="decrypt"> If true, the content will be decrypted </param>
        ///<param name="key"> The key to use for decryption </param>
        ///<param name="ivOrNonce"> The IV (for AES) or nonce (for ChaCha20) to use for decryption. NONCE NOT NECESSARY FOR READ IN CHACHA20</param>
        ///<param name="salt"> The salt to use for decryption. SALT NOT NECESARY IN CHACHA20</param>
        ///<param name="encryptionAlgorithm"> The encryption algorithm to use (AES or ChaCha20) </param>
        ///<returns> The file content as an array of lines </returns>
        ///<remarks> Default encryption algorithm is ChaCha20 </remarks>
        public static string[] Read(string filePath, int[]? linesToRead = null, bool decrypt = false, byte[]? key = null,
            byte[]? ivOrNonce = null, byte[]? salt = null, EncryptionAlgorithm encryptionAlgorithm = EncryptionAlgorithm.ChaCha20) {

            if (!System.IO.File.Exists(filePath)) throw new FileNotFoundException("File not found");

            string allText;

            if (decrypt) {
                byte[]? pkey = key;
                byte[]? pivOrNonce = ivOrNonce;
                byte[]? psalt = salt;

                byte[] decryptedBytes;
                var encryptedBytes = System.IO.File.ReadAllBytes(filePath);

                psalt ??= Aes.GenerateIv(filePath, filePath);

                switch (encryptionAlgorithm) {
                    case EncryptionAlgorithm.Aes:
                        pivOrNonce ??= Aes.GenerateIv(psalt, psalt);
                        pkey ??= Aes.GenerateKey(psalt, pivOrNonce);

                        pivOrNonce = Aes.GenerateIv(pivOrNonce, psalt);
                        pkey = Aes.GenerateKey(pkey, psalt);

                        decryptedBytes = Aes.Decrypt(
                            encryptedBytes,
                            pkey,
                            pivOrNonce);
                        break;
                    case EncryptionAlgorithm.ChaCha20:
                        pkey ??= ChaCha20.GenerateKey(psalt, psalt);

                        pkey = ChaCha20.GenerateKey(pkey, psalt);

                        decryptedBytes = ChaCha20.Decrypt(encryptedBytes, pkey);
                        break;
                    default:
                        throw new NotSupportedException("Unsupported encryption algorithm");
                }

                allText = Encoding.UTF8.GetString(decryptedBytes);

                CryptographicOperations.ZeroMemory(decryptedBytes);
                CryptographicOperations.ZeroMemory(encryptedBytes);
                CryptographicOperations.ZeroMemory(psalt);
                if(pivOrNonce != null) CryptographicOperations.ZeroMemory(pivOrNonce);
                CryptographicOperations.ZeroMemory(pkey);
            }
            else {
                allText = System.IO.File.ReadAllText(filePath);
            }

            var lines = allText.Split(["\r\n", "\r", "\n"], StringSplitOptions.None);

            if (linesToRead != null) {
                var selectedLines = new string[linesToRead.Length];
                for (var i = 0; i < linesToRead.Length; i++)
                    selectedLines[i] = lines[linesToRead[i]];

                return selectedLines;
            }
            else {
                return lines;
            }
        }

        ///<summary> Reads a file </summary>
        ///<param name="filePath"> The path to the file </param>
        ///<param name="decrypt"> If true, the content will be decrypted </param>
        ///<param name="key"> The key to use for decryption </param>
        ///<param name="ivOrNonce"> The IV (for AES) or nonce (for ChaCha20) to use for decryption. NONCE NOT NECESSARY FOR READ IN CHACHA20</param>
        ///<param name="salt"> The salt to use for decryption. SALT NOT NECESARY IN CHACHA20</param>
        ///<param name="encryptionAlgorithm"> The encryption algorithm to use (AES or ChaCha20) </param>
        ///<returns> The file content as an array of bytes </returns>
        ///<remarks> Default encryption algorithm is ChaCha20 </remarks>
        public static byte[] Read(byte[] filePath, bool decrypt = false, byte[]? key = null,
            byte[]? ivOrNonce = null, byte[]? salt = null, EncryptionAlgorithm encryptionAlgorithm = EncryptionAlgorithm.ChaCha20) {
            
            string? sfilePath = Encoding.UTF8.GetString(filePath);

            if (!System.IO.File.Exists(sfilePath)) throw new FileNotFoundException("File not found");

            byte[] allBytes;

            if (decrypt) {

                byte[]? pkey = key;
                byte[]? pivOrNonce = ivOrNonce;
                byte[]? psalt = salt;

                byte[] decryptedBytes;
                var encryptedBytes = System.IO.File.ReadAllBytes(sfilePath);
                sfilePath = null;

                psalt ??= Aes.GenerateIv(filePath, filePath);

                switch (encryptionAlgorithm) {
                    case EncryptionAlgorithm.Aes:
                        pivOrNonce ??= Aes.GenerateIv(psalt, psalt);
                        pkey ??= Aes.GenerateKey(psalt, pivOrNonce);

                        pivOrNonce = Aes.GenerateIv(pivOrNonce, psalt);
                        pkey = Aes.GenerateKey(pkey, psalt);

                        decryptedBytes = Aes.Decrypt(
                            encryptedBytes,
                            pkey,
                            pivOrNonce);
                        break;
                    case EncryptionAlgorithm.ChaCha20:
                        pkey ??= ChaCha20.GenerateKey(psalt, psalt);

                        pkey = ChaCha20.GenerateKey(pkey, psalt);

                        decryptedBytes = ChaCha20.Decrypt(encryptedBytes, pkey);
                        break;
                    default:
                        throw new NotSupportedException("Unsupported encryption algorithm");
                }

                CryptographicOperations.ZeroMemory(encryptedBytes);
                CryptographicOperations.ZeroMemory(psalt);
                if (pivOrNonce != null) CryptographicOperations.ZeroMemory(pivOrNonce);
                CryptographicOperations.ZeroMemory(pkey);

                return decryptedBytes;
            }
            else {
                allBytes = System.IO.File.ReadAllBytes(sfilePath);
                sfilePath = null;
                return allBytes;
            }
        }

        ///<summary> Writes multiple strings to a file </summary>
        ///<param name="filePath"> The path to the file </param>
        ///<param name="content"> The content to write </param>
        ///<param name="append"> If true, the content will be appended to the file, otherwise it will be overwritten </param>
        ///<param name="createIfNotExist"> If true, the file will be created if it does not exist </param>
        ///<param name="encrypt"> If true, the content will be encrypted </param>
        ///<param name="key"> The key to use for encryption </param>
        ///<param name="ivOrNonce"> The IV (for AES) or nonce (for ChaCha20) to use for encryption </param>
        ///<param name="salt"> The salt to use for encryption </param>
        ///<param name="encryptionAlgorithm"> The encryption algorithm to use (AES or ChaCha20) </param>
        ///<remarks> The method does not write each string of content in a new line, if you want to write in a new line, add "\n" at the end of each string </remarks>
        ///<remarks> If key or iv not provided, they will be generated but encryption will be less secure </remarks>
        public static void Write(string filePath, string[] content, bool append = true, bool createIfNotExist = true, bool encrypt = false,
            byte[]? key = null, byte[]? ivOrNonce = null, byte[]? salt = null, EncryptionAlgorithm encryptionAlgorithm = EncryptionAlgorithm.ChaCha20) {

            if (!System.IO.File.Exists(filePath)) {
                if (createIfNotExist) Create(filePath);
                else throw new FileNotFoundException("File not found");
            }

            var textToWrite = string.Join("\n", content);

            if (encrypt) {

                byte[]? pkey = key;
                byte[]? pivOrNonce = ivOrNonce;
                byte[]? psalt = salt;

                var existingText = "";
                string combinedText;
                byte[] existingEncryptedBytes;
                byte[] existingDecryptedBytes;
                byte[] combinedDecryptedBytes;
                byte[]? combinedEncryptedBytes = null;

                psalt ??= Aes.GenerateIv(filePath, filePath);

                switch (encryptionAlgorithm) {
                    case EncryptionAlgorithm.Aes:                  
                        pivOrNonce ??= Aes.GenerateIv(psalt, psalt);
                        pkey ??= Aes.GenerateKey(psalt, pivOrNonce);

                        pivOrNonce = Aes.GenerateIv(pivOrNonce, psalt);
                        pkey = Aes.GenerateKey(pkey, psalt);

                        if (append) {                            
                            existingEncryptedBytes = System.IO.File.ReadAllBytes(filePath);
                            existingDecryptedBytes = Aes.Decrypt(
                                existingEncryptedBytes,
                                pkey,
                                pivOrNonce);
                            existingText = Encoding.UTF8.GetString(existingDecryptedBytes);

                            CryptographicOperations.ZeroMemory(existingDecryptedBytes);
                            CryptographicOperations.ZeroMemory(existingEncryptedBytes);
                        }

                        combinedText = existingText + textToWrite;
                        combinedDecryptedBytes = Encoding.UTF8.GetBytes(combinedText);
                        combinedEncryptedBytes = Aes.Encrypt(
                            combinedDecryptedBytes,
                            pkey,
                            pivOrNonce);

                        CryptographicOperations.ZeroMemory(combinedDecryptedBytes);

                        break;
                    case EncryptionAlgorithm.ChaCha20:
                        pkey ??= ChaCha20.GenerateKey(psalt, psalt);
                        pivOrNonce ??= ChaCha20.GenerateNonce();

                        pkey = ChaCha20.GenerateKey(pkey, psalt);
                        pivOrNonce = ChaCha20.GenerateNonce(pivOrNonce, psalt);

                        if (append) {
                            existingEncryptedBytes = System.IO.File.ReadAllBytes(filePath);
                            existingDecryptedBytes = ChaCha20.Decrypt(existingEncryptedBytes, pkey);
                            existingText = Encoding.UTF8.GetString(existingDecryptedBytes);

                            CryptographicOperations.ZeroMemory(existingDecryptedBytes);
                            CryptographicOperations.ZeroMemory(existingEncryptedBytes);
                        }

                        combinedText = existingText + textToWrite;
                        combinedDecryptedBytes = Encoding.UTF8.GetBytes(combinedText);
                        combinedEncryptedBytes = ChaCha20.Encrypt(combinedDecryptedBytes, pkey, pivOrNonce);

                        CryptographicOperations.ZeroMemory(combinedDecryptedBytes);

                        break;
                }

                CryptographicOperations.ZeroMemory(psalt);
                CryptographicOperations.ZeroMemory(pivOrNonce);
                CryptographicOperations.ZeroMemory(pkey);

                System.IO.File.WriteAllBytes(filePath, combinedEncryptedBytes ?? Array.Empty<byte>());

                if(combinedEncryptedBytes != null) CryptographicOperations.ZeroMemory(combinedEncryptedBytes);

                return;
            }

            if (append) System.IO.File.AppendAllText(filePath, textToWrite);
            else System.IO.File.WriteAllText(filePath, textToWrite);
        }

        ///<summary> Writes multiple strings to a file </summary>
        ///<param name="filePath"> The path to the file </param>
        ///<param name="content"> The content to write </param>
        ///<param name="append"> If true, the content will be appended to the file, otherwise it will be overwritten </param>
        ///<param name="createIfNotExist"> If true, the file will be created if it does not exist </param>
        ///<param name="encrypt"> If true, the content will be encrypted </param>
        ///<param name="key"> The key to use for encryption </param>
        ///<param name="ivOrNonce"> The IV (for AES) or nonce (for ChaCha20) to use for encryption </param>
        ///<param name="salt"> The salt to use for encryption. ONLY USED IF KEY OR IV NOT PROVIDED </param>
        ///<param name="encryptionAlgorithm"> The encryption algorithm to use (AES or ChaCha20) </param>
        ///<remarks> If key or iv not provided, they will be generated but encryption will be less secure </remarks>
        public static void Write(byte[] filePath, byte[] content, bool append = true, bool createIfNotExist = true, bool encrypt = false,
            byte[]? key = null, byte[]? ivOrNonce = null, byte[]? salt = null, EncryptionAlgorithm encryptionAlgorithm = EncryptionAlgorithm.ChaCha20) {

            string? sfilePath = Encoding.UTF8.GetString(filePath);

            if (!System.IO.File.Exists(sfilePath)) {
                if (createIfNotExist) Create(sfilePath);
                else throw new FileNotFoundException("File not found");
            }

            byte[]? existingDecryptedBytes = null;
            byte[] combinedDecryptedBytes;

            if (encrypt) {

                byte[]? pkey = key;
                byte[]? pivOrNonce = ivOrNonce;
                byte[]? psalt = salt;

                byte[] existingEncryptedBytes;     
                byte[]? combinedEncryptedBytes = null;

                psalt ??= Aes.GenerateIv(filePath, filePath);

                switch (encryptionAlgorithm) {
                    case EncryptionAlgorithm.Aes:
                        pivOrNonce ??= Aes.GenerateIv(psalt, psalt);
                        pkey ??= Aes.GenerateKey(psalt, pivOrNonce);

                        pivOrNonce = Aes.GenerateIv(pivOrNonce, psalt);
                        pkey = Aes.GenerateKey(pkey, psalt);

                        if (append) {
                            existingEncryptedBytes = System.IO.File.ReadAllBytes(sfilePath);

                            existingDecryptedBytes = Aes.Decrypt(
                                existingEncryptedBytes,
                                pkey,
                                pivOrNonce);

                            CryptographicOperations.ZeroMemory(existingEncryptedBytes);
                        }

                        if(existingDecryptedBytes == null) existingDecryptedBytes = Array.Empty<byte>();

                        combinedDecryptedBytes = new byte[existingDecryptedBytes.Length + content.Length];

                        Array.Copy(existingDecryptedBytes, 0, combinedDecryptedBytes, 0, existingDecryptedBytes.Length);
                        Array.Copy(content, 0, combinedDecryptedBytes, existingDecryptedBytes.Length, content.Length);

                        combinedEncryptedBytes = Aes.Encrypt(
                            combinedDecryptedBytes,
                            pkey,
                            pivOrNonce);

                        CryptographicOperations.ZeroMemory(combinedDecryptedBytes);

                        break;
                    case EncryptionAlgorithm.ChaCha20:
                        pkey ??= ChaCha20.GenerateKey(psalt, psalt);
                        pivOrNonce ??= ChaCha20.GenerateNonce();

                        pkey = ChaCha20.GenerateKey(pkey, psalt);
                        pivOrNonce = ChaCha20.GenerateNonce(pivOrNonce, psalt);

                        if (append) {
                            existingEncryptedBytes = System.IO.File.ReadAllBytes(sfilePath);
                            existingDecryptedBytes = ChaCha20.Decrypt(existingEncryptedBytes, pkey);

                            CryptographicOperations.ZeroMemory(existingEncryptedBytes);
                        }

                        if (existingDecryptedBytes == null) existingDecryptedBytes = Array.Empty<byte>();

                        combinedDecryptedBytes = new byte[existingDecryptedBytes.Length + content.Length];

                        Array.Copy(existingDecryptedBytes, 0, combinedDecryptedBytes, 0, existingDecryptedBytes.Length);
                        Array.Copy(content, 0, combinedDecryptedBytes, existingDecryptedBytes.Length, content.Length);

                        combinedEncryptedBytes = ChaCha20.Encrypt(combinedDecryptedBytes, pkey, pivOrNonce);

                        CryptographicOperations.ZeroMemory(combinedDecryptedBytes);

                        break;
                }

                CryptographicOperations.ZeroMemory(psalt);
                CryptographicOperations.ZeroMemory(pivOrNonce);
                CryptographicOperations.ZeroMemory(pkey);

                System.IO.File.WriteAllBytes(sfilePath, combinedEncryptedBytes ?? Array.Empty<byte>());

                sfilePath = null;

                if (combinedEncryptedBytes != null) CryptographicOperations.ZeroMemory(combinedEncryptedBytes);

                return;
            }

            if (append) {
                existingDecryptedBytes = System.IO.File.ReadAllBytes(sfilePath);

                combinedDecryptedBytes = new byte[existingDecryptedBytes.Length + content.Length];

                Array.Copy(existingDecryptedBytes, 0, combinedDecryptedBytes, 0, existingDecryptedBytes.Length);
                Array.Copy(content, 0, combinedDecryptedBytes, existingDecryptedBytes.Length, content.Length);

                System.IO.File.WriteAllBytes(sfilePath, combinedDecryptedBytes);
                sfilePath = null;

                CryptographicOperations.ZeroMemory(existingDecryptedBytes);
                CryptographicOperations.ZeroMemory(combinedDecryptedBytes);
            }
            else {
                System.IO.File.WriteAllBytes(sfilePath, content);
                sfilePath = null;
            }
        }

        /// <summary> Re-encrypts a file with a new key and parameters. </summary>
        /// <param name="filePath">The path to the file to re-encrypt.</param>
        /// <param name="newKey">The new key to use for encryption.</param>
        /// <param name="newIvOrNonce">The new IV (for AES) or nonce (for ChaCha20) to use for encryption.</param>
        /// <param name="newSalt">The new salt to use for encryption (if applicable).</param>
        /// <param name="oldKey">The old key used for decryption.</param>
        /// <param name="oldIvOrNonce">The old IV (for AES) or nonce (for ChaCha20) used for decryption.</param>
        /// <param name="oldSalt">The old salt used for decryption (if applicable).</param>
        /// <param name="encryptionAlgorithm">The encryption algorithm to use (AES or ChaCha20).</param>
        public static void Reencrypt(string filePath, byte[] newKey, byte[] newIvOrNonce, byte[]? newSalt = null, byte[]? oldKey = null, 
            byte[]? oldIvOrNonce = null, byte[]? oldSalt = null, EncryptionAlgorithm encryptionAlgorithm = EncryptionAlgorithm.ChaCha20) {

            if (!System.IO.File.Exists(filePath)) throw new FileNotFoundException("File not found");

            byte[]? poldkey = oldKey;
            byte[]? poldivOrNonce = oldIvOrNonce;
            byte[]? poldsalt = oldSalt;

            var encryptedBytes = System.IO.File.ReadAllBytes(filePath);
            byte[]? decryptedBytes = null;

            poldsalt ??= Aes.GenerateIv(filePath, filePath);

            switch (encryptionAlgorithm) {
                case EncryptionAlgorithm.Aes:
                    poldivOrNonce ??= Aes.GenerateIv(poldsalt, poldsalt);
                    poldkey ??= Aes.GenerateKey(poldsalt, poldivOrNonce);
                    decryptedBytes = Aes.Decrypt(encryptedBytes, poldkey, poldivOrNonce);
                    break;
                case EncryptionAlgorithm.ChaCha20:
                    poldkey ??= ChaCha20.GenerateKey(poldsalt, poldsalt);
                    decryptedBytes = ChaCha20.Decrypt(encryptedBytes, poldkey);
                    break;
            }

            decryptedBytes ??= Array.Empty<byte>();

            var reencryptedBytes = encryptionAlgorithm switch {
                EncryptionAlgorithm.Aes => Aes.Encrypt(decryptedBytes, newKey, newIvOrNonce),
                EncryptionAlgorithm.ChaCha20 => ChaCha20.Encrypt(decryptedBytes, newKey, newIvOrNonce),
                _ => throw new NotSupportedException("Unsupported encryption algorithm"),
            };

            System.IO.File.WriteAllBytes(filePath, reencryptedBytes);

            CryptographicOperations.ZeroMemory(decryptedBytes);
            CryptographicOperations.ZeroMemory(encryptedBytes);
            CryptographicOperations.ZeroMemory(reencryptedBytes);

            CryptographicOperations.ZeroMemory(poldkey);
            CryptographicOperations.ZeroMemory(poldivOrNonce);
            CryptographicOperations.ZeroMemory(poldsalt);
        }

        /// <summary> Re-encrypts a file with a new key and parameters. </summary>
        /// <param name="filePath">The path to the file to re-encrypt.</param>
        /// <param name="newKey">The new key to use for encryption.</param>
        /// <param name="newIvOrNonce">The new IV (for AES) or nonce (for ChaCha20) to use for encryption.</param>
        /// <param name="newSalt">The new salt to use for encryption (if applicable).</param>
        /// <param name="oldKey">The old key used for decryption.</param>
        /// <param name="oldIvOrNonce">The old IV (for AES) or nonce (for ChaCha20) used for decryption.</param>
        /// <param name="oldSalt">The old salt used for decryption (if applicable).</param>
        /// <param name="encryptionAlgorithm">The encryption algorithm to use (AES or ChaCha20).</param>
        public static void Reencrypt(byte[] filePath, byte[] newKey, byte[] newIvOrNonce, byte[]? newSalt = null, byte[]? oldKey = null,
            byte[]? oldIvOrNonce = null, byte[]? oldSalt = null, EncryptionAlgorithm encryptionAlgorithm = EncryptionAlgorithm.ChaCha20) {
            string? sfilePath = Encoding.UTF8.GetString(filePath);
            Reencrypt(sfilePath, newKey, newIvOrNonce, newSalt, oldKey, oldIvOrNonce, oldSalt, encryptionAlgorithm);
            sfilePath = null;
        }

        ///<summary> Renames a file </summary>
        ///<param name="filePath"> The path to the file </param>
        ///<param name="newName"> The new name of the file (not the new path, only the new name) </param>
        ///<returns> The new path to the file </returns>
        public static string Rename(string filePath, string newName){
            if(!System.IO.File.Exists(filePath)) throw new FileNotFoundException("File not found");

            var parentDirectory = Directory.GetParent(filePath);
            string parentPath;

            if(parentDirectory != null) parentPath = parentDirectory.FullName; 
            else throw new IOException("Invalid path");

            var newPath = Path.Combine(parentPath, newName);
            if(System.IO.File.Exists(newPath)) throw new IOException("File already exists");
            System.IO.File.Move(filePath, newPath);

            return newPath;
        }

        ///<summary> Renames a file </summary>
        ///<param name="filePath"> The bytes of the path to the file </param>
        ///<param name="newName"> The bytes of the new name of the file (not the new path, only the new name) </param>
        ///<returns> The bytes of the new path to the file </returns>
        public static byte[] Rename(byte[] filePath, byte[] newName) {
            string? sfilePath = Encoding.UTF8.GetString(filePath);
            string? snewName = Encoding.UTF8.GetString(newName);

            if (!System.IO.File.Exists(sfilePath)) throw new FileNotFoundException("File not found");

            var parentDirectory = Directory.GetParent(sfilePath);
            string? parentPath;

            if (parentDirectory != null) parentPath = parentDirectory.FullName;
            else {
                sfilePath = null;
                snewName = null;
                throw new IOException("Invalid path");
            }

            string? newPath = Path.Combine(parentPath, snewName);
            if (System.IO.File.Exists(newPath)) throw new IOException("File already exists");
            System.IO.File.Move(sfilePath, newPath);

            sfilePath = null;
            snewName = null;
            parentPath = null;

            byte[] bnewPath = Encoding.UTF8.GetBytes(newPath);

            newPath = null;

            return bnewPath;
        }

        ///<summary> Creates a file with the specified content </summary>
        ///<param name="filePath"> The path to the file </param>
        ///<param name="content"> The content of the file </param>
        ///<param name="overwrite"> If true, the file will be overwritten if it already exists </param>
        public static void Create(string filePath, string content = "", bool overwrite = false) {
            if (!overwrite && System.IO.File.Exists(filePath)) throw new IOException("File already exists");

            using(var fileStream = new FileStream(filePath, FileMode.Create, FileAccess.Write)){
                var info = new UTF8Encoding(true).GetBytes(content);
                fileStream.Write(info, 0, info.Length);
            }
        }

        ///<summary> Creates a file with the specified content </summary>
        ///<param name="filePath"> The path to the file </param>
        ///<param name="content"> The content of the file </param>
        ///<param name="overwrite"> If true, the file will be overwritten if it already exists otherwise an exception will be thrown if the file already exists </param>
        public static void Create(byte[] filePath, byte[]? content = null, bool overwrite = false) {
            string? sfilePath = Encoding.UTF8.GetString(filePath);

            if (!overwrite && System.IO.File.Exists(sfilePath)) {
                sfilePath = null;
                throw new IOException("File already exists");
            }

            if(content == null) content = Array.Empty<byte>();
            using (var fileStream = new FileStream(sfilePath, FileMode.Create, FileAccess.Write)) {
                fileStream.Write(content, 0, content.Length);
            }

            sfilePath = null;
        }

        ///<summary> Deletes a file </summary>
        ///<param name="filePath"> The path to the file </param>
        public static void Delete(string filePath) {
            if (!System.IO.File.Exists(filePath)) throw new FileNotFoundException("File not found");
            System.IO.File.Delete(filePath);
        }

        ///<summary> Deletes a file </summary>
        ///<param name="filePath"> The path to the file </param>
        public static void Delete(byte[] filePath) {
            string? sfilePath = Encoding.UTF8.GetString(filePath);

            if (!System.IO.File.Exists(sfilePath)) {
                sfilePath = null;
                throw new FileNotFoundException("File not found");
            }

            System.IO.File.Delete(sfilePath);
            sfilePath = null;
        }

        ///<summary> Checks if a file exists </summary>
        ///<param name="filePath"> The path to the file </param>
        ///<returns> True if the file exists, false otherwise </returns>
        public static bool Exists(string filePath) => System.IO.File.Exists(filePath);

        ///<summary> Checks if a file exists </summary>
        ///<param name="filePath"> The path to the file </param>
        ///<returns> True if the file exists, false otherwise </returns>
        public static bool Exists(byte[] filePath) {
            string? sfilePath = Encoding.UTF8.GetString(filePath);
            bool exists = System.IO.File.Exists(sfilePath);
            sfilePath = null;
            return exists;
        }

        ///<summary> Returns the number of lines in a file </summary>
        ///<param name="filePath"> The path to the file </param>
        ///<returns> The number of lines in the file </returns>
        ///<remarks> If the file is encrypted, it will be decrypted to count the lines, so the decrypted content will remain plaintext on memory so it is not safe. </remarks>
        public static int NumberOfLines(string filePath, bool decrypt = false, byte[]? key = null,
            byte[]? ivOrNonce = null, byte[]? salt = null, EncryptionAlgorithm encryptionAlgorithm = EncryptionAlgorithm.ChaCha20) {
            if(!System.IO.File.Exists(filePath)) throw new FileNotFoundException("File not found");

            string[]? content = Read(filePath, decrypt: decrypt, key: key, ivOrNonce: ivOrNonce, salt: salt, encryptionAlgorithm: encryptionAlgorithm);
            int lines = content.Length;
            content = null;
            return lines;
        }

        ///<summary> Returns the number of lines in a file </summary>
        ///<param name="filePath"> The path to the file </param>
        ///<returns> The number of lines in the file </returns>
        public static int NumberOfLines(byte[] filePath, bool decrypt = false, byte[]? key = null,
            byte[]? ivOrNonce = null, byte[]? salt = null, EncryptionAlgorithm encryptionAlgorithm = EncryptionAlgorithm.ChaCha20) {
            string? sfilePath = Encoding.UTF8.GetString(filePath);
            if (!System.IO.File.Exists(sfilePath)) throw new FileNotFoundException("File not found");

            sfilePath = null;

            byte[]? content = Read(filePath, decrypt: decrypt, key: key, ivOrNonce: ivOrNonce, salt: salt, encryptionAlgorithm: encryptionAlgorithm);
            int lines = content.Length;

            CryptographicOperations.ZeroMemory(content);

            content = null;
            return lines;
        }
    }
}
