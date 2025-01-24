using System.Text;

namespace SimpleFiles {
    public static class Folder{
        ///<summary> Creates a folder </summary>
        ///<param name="folderPath"> The path to the folder </param>
        public static void Create(string folderPath){
            if (Directory.Exists(folderPath)) throw new IOException("Folder already exists");
            Directory.CreateDirectory(folderPath);
        }

        ///<summary> Creates a folder </summary>
        ///<param name="folderPath"> The path to the folder </param>
        public static void Create(byte[] folderPath) {
            string? sfolderPath = Encoding.UTF8.GetString(folderPath);
            if (Directory.Exists(sfolderPath)) {
                sfolderPath = null;
                throw new IOException("Folder already exists");              
            }
            Directory.CreateDirectory(sfolderPath);
            sfolderPath = null;
        }

        ///<summary> Deletes a folder </summary>
        ///<param name="folderPath"> The path to the folder </param>
        ///<param name="deleteRecursive"> If true, deletes the folder and all its content. If false, deletes the folder only if it is empty </param>
        public static void Delete(string folderPath, bool deleteRecursive = false){
            if (!Directory.Exists(folderPath)) throw new IOException("Folder does not exist");
            Directory.Delete(folderPath, deleteRecursive);
        }

        ///<summary> Deletes a folder </summary>
        ///<param name="folderPath"> The path to the folder </param>
        ///<param name="deleteRecursive"> If true, deletes the folder and all its content. If false, deletes the folder only if it is empty </param>
        public static void Delete(byte[] folderPath, bool deleteRecursive = false) {
            string? sfolderPath = Encoding.UTF8.GetString(folderPath);
            if (!Directory.Exists(sfolderPath)) {
                sfolderPath = null;
                throw new IOException("Folder does not exist");
            }
            Directory.Delete(sfolderPath, deleteRecursive);
            sfolderPath = null;
        }

        ///<summary> Renames a folder </summary>
        ///<param name="folderPath"> The path to the folder </param>
        ///<param name="newName"> The new name of the folder (not the new path, only the new name) </param>
        ///<returns> The new path to the folder </returns>
        public static string Rename(string folderPath, string newName){
            if (!Directory.Exists(folderPath)) throw new IOException("Folder does not exist");

            var parentDirectory = Directory.GetParent(folderPath);
            string parentPath;

            if (parentDirectory != null) parentPath = parentDirectory.FullName;
            else throw new IOException("Invalid path");

            var newPath = Path.Combine(parentPath, newName);

            if (Directory.Exists(newPath)) throw new IOException("Folder already exists");
            Directory.Move(folderPath, newPath);

            return newPath;
        }

        ///<summary> Renames a folder </summary>
        ///<param name="folderPath"> The path to the folder </param>
        ///<param name="newName"> The new name of the folder (not the new path, only the new name) </param>
        ///<returns> The new path to the folder </returns>
        public static byte[] Rename(byte[] folderPath, byte[] newName) {
            string? sfolderPath = Encoding.UTF8.GetString(folderPath);
           
            if (!Directory.Exists(sfolderPath)) {
                sfolderPath = null;
                throw new IOException("Folder does not exist");
            }

            string? snewName = Encoding.UTF8.GetString(newName);

            var parentDirectory = Directory.GetParent(sfolderPath);
            string? parentPath;

            if (parentDirectory != null) parentPath = parentDirectory.FullName;
            else {
                sfolderPath = null;
                snewName = null;
                throw new IOException("Invalid path");
            }

            string? newPath = Path.Combine(parentPath, snewName);

            if (Directory.Exists(newPath)) throw new IOException("Folder already exists");
            Directory.Move(sfolderPath, newPath);

            byte[] bnewPath = Encoding.UTF8.GetBytes(newPath);

            sfolderPath = null;
            snewName = null;
            parentPath = null;
            newPath = null;

            return bnewPath;
        }

        ///<summary> Moves a folder </summary>
        ///<param name="folderPath"> The path to the folder </param>
        ///<param name="newPath"> The new path to the folder </param>
        public static void Move(string folderPath, string newPath){
            if (!Directory.Exists(folderPath)) throw new IOException("Folder does not exist");
            if (Directory.Exists(newPath)) throw new IOException("Folder already exists");
            Directory.Move(folderPath, newPath);
        }

        ///<summary> Moves a folder </summary>
        ///<param name="folderPath"> The path to the folder </param>
        ///<param name="newPath"> The new path to the folder </param>
        public static void Move(byte[] folderPath, byte[] newPath) {
            string? sfolderPath = Encoding.UTF8.GetString(folderPath);

            if (!Directory.Exists(sfolderPath)) {
                sfolderPath = null;
                throw new IOException("Folder does not exist");
            }

            string? snewPath = Encoding.UTF8.GetString(newPath);

            if (Directory.Exists(snewPath)) {
                sfolderPath = null;
                snewPath = null;
                throw new IOException("Folder already exists");
            }

            Directory.Move(sfolderPath, snewPath);

            sfolderPath = null;
            snewPath = null;
        }

        ///<summary> Copies a folder </summary>
        ///<param name="folderPath"> The path to the folder </param>
        ///<param name="newPath"> The new path to the folder </param>
        public static void Copy(string folderPath, string newPath){
            if (!Directory.Exists(folderPath)) throw new IOException("Folder does not exist");
            if (Directory.Exists(newPath)) throw new IOException("Folder already exists");
            Directory.CreateDirectory(newPath);

            foreach (string file in Directory.GetFiles(folderPath))
                System.IO.File.Copy(file, Path.Combine(newPath, Path.GetFileName(file)));

            foreach (string folder in Directory.GetDirectories(folderPath))
                Copy(folder, Path.Combine(newPath, Path.GetFileName(folder)));
        }

        ///<summary> Copies a folder </summary>
        ///<param name="folderPath"> The path to the folder </param>
        ///<param name="newPath"> The new path to the folder </param>
        public static void Copy(byte[] folderPath, byte[] newPath) {
            string? sfolderPath = Encoding.UTF8.GetString(folderPath);

            if (!Directory.Exists(sfolderPath)) {
                sfolderPath = null;
                throw new IOException("Folder does not exist");
            }

            string? snewPath = Encoding.UTF8.GetString(newPath);

            if (Directory.Exists(snewPath)) {
                sfolderPath = null;
                snewPath = null;
                throw new IOException("Folder already exists");
            }

            Directory.CreateDirectory(snewPath);

            foreach (string file in Directory.GetFiles(sfolderPath))
                System.IO.File.Copy(file, Path.Combine(snewPath, Path.GetFileName(file)));
                
            foreach (string folder in Directory.GetDirectories(sfolderPath))
                Copy(folder, Path.Combine(snewPath, Path.GetFileName(folder)));

            sfolderPath = null;
            snewPath = null;
        }

        ///<summary> Checks if a folder exists </summary>
        ///<param name="folderPath"> The path to the folder </param>
        ///<returns> True if the folder exists, false otherwise </returns>
        public static bool Exists(string folderPath){
            return Directory.Exists(folderPath);
        }

        ///<summary> Checks if a folder exists </summary>
        ///<param name="folderPath"> The path to the folder </param>
        ///<returns> True if the folder exists, false otherwise </returns>
        public static bool Exists(byte[] folderPath) {
            string? sfolderPath = Encoding.UTF8.GetString(folderPath);
            bool exists = Directory.Exists(sfolderPath);     
            sfolderPath = null;
            return exists;
        }

        ///<summary> Gets the number of files in a folder </summary>
        ///<param name="folderPath"> The path to the folder </param>
        ///<param name="recursive"> If true, counts all files in all subdirectories. If false, counts only the files in the given directory </param>
        public static int GetNumberOfFiles(string folderPath, bool recursive = false) {
            if (!Directory.Exists(folderPath))
                throw new DirectoryNotFoundException($"The directory '{folderPath}' does not exist.");

            return Directory.GetFiles(folderPath, "*", recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly).Length;
        }

        ///<summary> Gets the number of files in a folder </summary>
        ///<param name="folderPath"> The path to the folder </param>
        ///<param name="recursive"> If true, counts all files in all subdirectories. If false, counts only the files in the given directory </param>
        public static int GetNumberOfFiles(byte[] folderPath, bool recursive = false) {
            string? sfolderPath = Encoding.UTF8.GetString(folderPath);
            if (!Directory.Exists(sfolderPath)) {
                sfolderPath = null;
                throw new DirectoryNotFoundException($"The directory does not exist.");
            }
            int amount = Directory.GetFiles(sfolderPath, "*", recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly).Length;
            sfolderPath = null;
            return amount;
        }

        ///<summary> Gets the number of folders in a folder </summary>
        ///<param name="folderPath"> The path to the folder </param>
        ///<param name="recursive"> If true, counts all folders in all subdirectories. If false, counts only the folders in the given directory </param>
        public static int GetNumberOfFolders(string folderPath, bool recursive = false) {
            if (!Directory.Exists(folderPath))
                throw new DirectoryNotFoundException($"The directory '{folderPath}' does not exist.");

            return Directory.GetDirectories(folderPath, "*", recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly).Length;
        }

        ///<summary> Gets the number of folders in a folder </summary>
        ///<param name="folderPath"> The path to the folder </param>
        ///<param name="recursive"> If true, counts all folders in all subdirectories. If false, counts only the folders in the given directory </param>
        public static int GetNumberOfFolders(byte[] folderPath, bool recursive = false) {
            string? sfolderPath = Encoding.UTF8.GetString(folderPath);
            if (!Directory.Exists(sfolderPath)) {
                sfolderPath = null;
                throw new DirectoryNotFoundException($"The directory does not exist.");
            }
            int amount = Directory.GetDirectories(sfolderPath, "*", recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly).Length;
            sfolderPath = null;
            return amount;
        }

        ///<summary> Gets the first file with the given extension </summary>
        ///<param name="directoryPath"> The path to the directory </param>
        ///<param name="extension"> The extension of the file </param>
        ///<param name="recursive"> If true, searches in all subdirectories. If false, searches only in the given directory </param>
        public static string? GetFirstFileWithExtension(string directoryPath, string extension, bool recursive = true) {
            if (!Directory.Exists(directoryPath))
                throw new DirectoryNotFoundException($"The directory '{directoryPath}' does not exist.");

            string[] files = Directory.GetFiles(directoryPath, $"*{extension}", recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly);

            return files.Length > 0 ? files[0] : null;
        }

        ///<summary> Gets the first file with the given extension </summary>
        ///<param name="directoryPath"> The path to the directory </param>
        ///<param name="extension"> The extension of the file </param>
        ///<param name="recursive"> If true, searches in all subdirectories. If false, searches only in the given directory </param>
        public static byte[]? GetFirstFileWithExtension(byte[] directoryPath, byte[] extension, bool recursive = true) {
            string? sdirectoryPath = Encoding.UTF8.GetString(directoryPath);
            if (!Directory.Exists(sdirectoryPath)) {
                sdirectoryPath = null;
                throw new DirectoryNotFoundException($"The directory does not exist.");
            }
            
            string? sextension = Encoding.UTF8.GetString(extension);

            string[] files = Directory.GetFiles(sdirectoryPath, $"*{sextension}", recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly);
            byte[]? result = files.Length > 0 ? Encoding.UTF8.GetBytes(files[0]) : null;

            sextension = null;
            sdirectoryPath = null;

            return result;
        }

        ///<summary> Gets all files with the given extension </summary>
        ///<param name="directoryPath"> The path to the directory </param>
        ///<param name="extension"> The extension of the files </param>
        ///<param name="recursive"> If true, searches in all subdirectories. If false, searches only in the given directory</param>
        ///<returns> An array with all the files with the given extension </returns>
        public static string[] GetAllFilesWithExtension(string directoryPath, string extension, bool recursive = true) {
            if(!Directory.Exists(directoryPath))
                throw new DirectoryNotFoundException($"The directory '{directoryPath}' does not exist.");

            return Directory.GetFiles(directoryPath, $"*{extension}", recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly);     
        }

        ///<summary> Gets all files with the given extension </summary>
        ///<param name="directoryPath"> The path to the directory </param>
        ///<param name="extension"> The extension of the files </param>
        ///<param name="recursive"> If true, searches in all subdirectories. If false, searches only in the given directory</param>
        ///<returns> An array with all the files with the given extension </returns>
        public static byte[][] GetAllFilesWithExtension(byte[] directoryPath, byte[] extension, bool recursive = true) {
            string? sdirectoryPath = Encoding.UTF8.GetString(directoryPath);
            if (!Directory.Exists(sdirectoryPath)) {
                sdirectoryPath = null;
                throw new DirectoryNotFoundException($"The directory does not exist.");
            }
                
            string? sextension = Encoding.UTF8.GetString(extension);

            string[]? files = Directory.GetFiles(sdirectoryPath, $"*{sextension}", recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly);

            sdirectoryPath = null;
            sextension = null;

            byte[][] result = new byte[files.Length][];

            for(int i = 0; i < files.Length; i++)  result[i] = Encoding.UTF8.GetBytes(files[i]);
            
            files = null;
            return result;
        }

        ///<summary> Gets all files in a folder </summary>
        ///<param name="directoryPath"> The path to the directory </param>
        ///<param name="recursive"> If true, searches in all subdirectories. If false, searches only in the given directory </param>
        ///<returns> An array with all the full paths to the files </returns>
        public static string[] GetAllFiles(string directoryPath, bool recursive = true) {
            if (!Directory.Exists(directoryPath))
                throw new DirectoryNotFoundException($"The directory '{directoryPath}' does not exist.");

            return Directory.GetFiles(directoryPath, "*", recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly);
        }

        ///<summary> Gets all files in a folder </summary>
        ///<param name="directoryPath"> The path to the directory </param>
        ///<param name="recursive"> If true, searches in all subdirectories. If false, searches only in the given directory </param>
        ///<returns> An array with all the full paths to the files </returns>
        public static byte[][] GetAllFiles(byte[] directoryPath, bool recursive = true) {
            string? sdirectoryPath = Encoding.UTF8.GetString(directoryPath);
            if (!Directory.Exists(sdirectoryPath)) {
                sdirectoryPath = null;
                throw new DirectoryNotFoundException($"The directory does not exist.");
            }
            string[]? files = Directory.GetFiles(sdirectoryPath, "*", recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly);

            byte[][] result = new byte[files.Length][];
            for (int i = 0; i < files.Length; i++) result[i] = Encoding.UTF8.GetBytes(files[i]);

            files = null;
            sdirectoryPath = null;
            return result;
        }

        ///<summary> Gets all folders in a folder </summary>
        ///<param name="directoryPath"> The path to the directory </param>
        ///<param name="recursive"> If true, searches in all subdirectories. If false, searches only in the given directory </param>
        ///<returns> An array with all the full paths to the folders </returns>
        public static string[] GetAllFolders(string directoryPath, bool recursive = true) {
            if (!Directory.Exists(directoryPath))
                throw new DirectoryNotFoundException($"The directory '{directoryPath}' does not exist.");

            return Directory.GetDirectories(directoryPath, "*", recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly);
        }

        ///<summary> Gets all folders in a folder </summary>
        ///<param name="directoryPath"> The path to the directory </param>
        ///<param name="recursive"> If true, searches in all subdirectories. If false, searches only in the given directory </param>
        ///<returns> An array with all the full paths to the folders </returns>
        public static byte[][] GetAllFolders(byte[] directoryPath, bool recursive = true) {
            string? sdirectoryPath = Encoding.UTF8.GetString(directoryPath);
            if (!Directory.Exists(sdirectoryPath)) {
                sdirectoryPath = null;
                throw new DirectoryNotFoundException($"The directory does not exist.");
            }

            string[]? folders = Directory.GetDirectories(sdirectoryPath, "*", recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly);

            byte[][] result = new byte[folders.Length][];
            for (int i = 0; i < folders.Length; i++) result[i] = Encoding.UTF8.GetBytes(folders[i]);

            folders = null;
            sdirectoryPath = null;
            return result;
        }

        ///<summary> Checks if a folder is empty </summary>
        ///<param name="folderPath"> The path to the folder </param>
        public static bool IsEmpty(string folderPath) {
            return Directory.GetFiles(folderPath).Length == 0 && Directory.GetDirectories(folderPath).Length == 0;
        }

        ///<summary> Checks if a folder is empty </summary>
        ///<param name="folderPath"> The path to the folder </param>
        public static bool IsEmpty(byte[] folderPath) {
            string? sfolderPath = Encoding.UTF8.GetString(folderPath);
            bool isEmpty = Directory.GetFiles(sfolderPath).Length == 0 && Directory.GetDirectories(sfolderPath).Length == 0;
            sfolderPath = null;
            return isEmpty;
        }

        ///<summary> Empties the content of a folder </summary>
        ///<param name="folderPath"> The path to the folder </param>
        public static void EmptyContent(string folderPath) {
            foreach (string file in Directory.GetFiles(folderPath)) System.IO.File.Delete(file);
            foreach (string folder in Directory.GetDirectories(folderPath)) Directory.Delete(folder, true);
        }

        ///<summary> Empties the content of a folder </summary>
        ///<param name="folderPath"> The path to the folder </param>
        public static void EmptyContent(byte[] folderPath) {
            string? sfolderPath = Encoding.UTF8.GetString(folderPath);
            foreach (string file in Directory.GetFiles(sfolderPath)) System.IO.File.Delete(file);
            foreach (string folder in Directory.GetDirectories(sfolderPath)) Directory.Delete(folder, true);
            sfolderPath = null;
        }
    }
}
