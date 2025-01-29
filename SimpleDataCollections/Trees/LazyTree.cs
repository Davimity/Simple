using SimpleDataCollections.Tree;
using System.Text;
using System.Text.Json;

using File = SimpleFiles.File;

namespace SimpleDataCollections.Trees {
    public class LazyTree<T> : Tree<T> {
        #region Variables

            private bool _childrenLoaded = false;
            private string path;

        #endregion

        #region Properties

            public bool ChildrenLoaded {
                get => _childrenLoaded;
            }

        #endregion

        #region Constructors

            public LazyTree(T value, string path) : base(value) {
                this.path = path;
            }

            public LazyTree(T value, byte[] path) : base(value) {
                this.path = Encoding.UTF8.GetString(path);
            }

        #endregion

        #region Public methods

            ///<summary> Loads the children of the tree from a file. </summary>
            ///<param name="encrypted"> Whether the file is encrypted. </param>
            ///<param name="key"> The key to decrypt the file. </param>
            ///<param name="ivOrNonce"> The IV or nonce to decrypt the file. </param>
            ///<param name="salt"> The salt used to decrypt the file. </param>
            ///<param name="encryptionAlgorithm"> The encryption algorithm used to decrypt the file. </param>
            public void LoadChildrenFromFile(bool encrypted = false, byte[]? key = null, byte[]? ivOrNonce = null,
                byte[]? salt = null, File.EncryptionAlgorithm encryptionAlgorithm = File.EncryptionAlgorithm.ChaCha20) {
                if (_childrenLoaded) return;

                if (!File.Exists(path)) {
                    _childrenLoaded = true;
                    return;
                }

                byte[] fileBytes = File.Read(Encoding.UTF8.GetBytes(path), decrypt: encrypted, key: key, ivOrNonce: ivOrNonce, salt: salt, encryptionAlgorithm: encryptionAlgorithm);

                if(fileBytes.Length == 0) return;

                try {
                    List<Tree<T>>? children = JsonSerializer.Deserialize<List<Tree<T>>>(fileBytes);
                    if (children == null) return;

                    foreach (var child in children) AddChild(child);
                    _childrenLoaded = true;
                }catch(Exception e) {
                    _childrenLoaded = false;
                    throw new Exception("Error while loading children from file.", e);
                }
            }

            ///<summary> Unloads the children of the tree. </summary>
            ///<param name="saveBeforeUnload"> Whether the children should be saved before unloading. </param>
            ///<param name="encrypted"> Whether the children should be saved before unloading. </param>
            ///<param name="key"> The key to encrypt the children. </param>
            ///<param name="ivOrNonce"> The IV or nonce to encrypt the children. </param>
            ///<param name="salt"> The salt used to encrypt the children. </param>
            ///<param name="encryptionAlgorithm"> The encryption algorithm used to encrypt the children. </param>
            public void UnloadChildren(bool saveBeforeUnload = true, bool encrypted = false, byte[]? key = null, byte[]? ivOrNonce = null,
                byte[]? salt = null, File.EncryptionAlgorithm encryptionAlgorithm = File.EncryptionAlgorithm.ChaCha20) {
                if (!_childrenLoaded) return;

                if (saveBeforeUnload) SaveChildrenToFile(encrypted, key, ivOrNonce, salt, encryptionAlgorithm);

                RemoveChildren();
                _childrenLoaded = false;
            }

            ///<summary> Saves the children of the tree to a file. </summary>
            ///<param name="encrypted"> Whether the file should be encrypted. </param>
            ///<param name="key"> The key to encrypt the file. </param>
            ///<param name="ivOrNonce"> The IV or nonce to encrypt the file. </param>
            ///<param name="salt"> The salt used to encrypt the file. </param>
            ///<param name="encryptionAlgorithm"> The encryption algorithm used to encrypt the file. </param>
            public void SaveChildrenToFile(bool encrypted = false, byte[]? key = null, byte[]? ivOrNonce = null,
                byte[]? salt = null, File.EncryptionAlgorithm encryptionAlgorithm = File.EncryptionAlgorithm.ChaCha20) {
               
                if(!File.Exists(path)) return;

                List<Tree<T>>[] grandchildren = new List<Tree<T>>[Children.Count];

                for (int i = 0; i < grandchildren.Length; i++) {
                    grandchildren[i] = new List<Tree<T>>(Children[i].Children);
                    Children[i].RemoveChildren(false);
                }

                var children = new List<Tree<T>>(Children);

                try {
                    byte[] data = JsonSerializer.SerializeToUtf8Bytes(children);

                    File.Write(Encoding.UTF8.GetBytes(path), data, append: false, encrypt: encrypted, key: key, ivOrNonce: ivOrNonce, salt: salt, encryptionAlgorithm: encryptionAlgorithm);

                    for (int i = 0; i < grandchildren.Length; i++) {
                        Children[i].AddChildren(grandchildren[i]);
                        grandchildren[i].Clear();
                    }
                }catch(Exception e) {
                    throw new Exception("Error while saving children to file.", e);
                }
            }

        #endregion
    }
}
