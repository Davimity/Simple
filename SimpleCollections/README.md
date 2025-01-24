# 🌳 SimpleCollections Library

The **SimpleCollections Library** is your go-to solution for advanced data structures in .NET. It provides a variety of tree implementations that are optimized for flexibility, performance, and extensibility. Whether you need hierarchical data or lazy-loaded trees, we've got you covered! 🚀

---

## 🚀 Features

### Data Structures 🌲
- **`Tree<T>`**:
  - A flexible, generic tree structure.
  - Supports operations like depth-first and breadth-first traversal, searching, and dynamic manipulation of nodes.
- **`LazyTree<T>`**:
  - Extends `Tree<T>` with lazy-loading functionality.
  - Load and unload children dynamically from files with optional encryption support.

### Security 🛡️
- **Encryption Support**:
  - Save and load `LazyTree<T>` nodes securely using AES or ChaCha20 encryption.
- **Memory Safety**:
  - Clears sensitive data from memory after use.

---

## 📚 Installation

Install the library via NuGet:

```bash
dotnet add package SimpleCollections
```

---

## 📝 Usage

Creating a Tree
```csharp
var tree = new Tree<string>("Root");
tree.AddChild("Child 1");
tree.AddChild("Child 2");
```

Traversing the Tree
```csharp
tree.DepthFirstTraverse(node => Console.WriteLine(node.Value));
```

Using LazyTree
```csharp
var lazyTree = new LazyTree<string>("Root", "path/to/data.json");
lazyTree.LoadChildrenFromFile(encrypted: true, key: encryptionKey, ivOrNonce: iv);
```

---

## 📌 Why Choose SimpleCollections?

- **Focus on Flexibility**: Tailored solutions for hierarchical data needs.
- **Security**: Built-in support for encrypted lazy loading and saving.
- **Performance**: Efficient traversal and manipulation of nodes.
- ***Ease of Use**: Intuitive API for developers.

---

## 💡 Examples

Finding a Node
```csharp
var foundNode = tree.FindFirst(value => value == "Child 1");
Console.WriteLine(foundNode?.Value);
```

Lazy Loading Children
```csharp
lazyTree.LoadChildrenFromFile(encrypted: true, key: myKey, ivOrNonce: myIv);
lazyTree.UnloadChildren(saveBeforeUnload: true);
```

---

## 📦 Contributions

Contributions are welcome! Feel free to submit issues or pull requests.

---

## 🏷️ License

This project is licensed under the MIT License.