using System.Text.Json.Serialization;
using System.Text.Json;

using System.Collections;

namespace SimpleUtilities.DataStructures {
    public class Tree<T> : IDisposable, IEnumerable<Tree<T>>{
        #region Variables

            private T _value;
            private List<Tree<T>> _children = [];
            private Tree<T>? _parent;

        #endregion

        #region Properties

            public T Value {
                get => _value;
                set {
                    _value = value;
                }
            }

            public List<Tree<T>> Children => _children;

            public Tree<T>? Parent => _parent;

        #endregion

        #region Constructors

            public Tree(T value) {
                _value = value;
            }

        #endregion

        #region Public methods

            ///<summary> Adds a child to the tree. </summary>
            ///<param name="data"> The data to be added to the child. </param>
            public void AddChild(T data) {
                Tree<T> child = new(data);
                child._parent = this;
                _children.Add(child);
            }

            ///<summary> Adds a tree as a child to the current tree. </summary>
            ///<param name="child"> The tree to be added as a child. </param>
            public void AddChild(Tree<T> child) {
                _children.Add(child);
                child._parent = this;
            }

            ///<summary> Adds a list of trees as children to the current tree. </summary>
            ///<param name="children"> The list of trees to be added as children. </param>
            public void AddChildren(List<Tree<T>> children) {
                foreach (var child in children) {
                    _children.Add(child);
                    child._parent = this;
                }
            }

            ///<summary> Removes a child from the tree. </summary>
            ///<param name="child"> The child to be removed. </param>
            ///<param name="disposeChild"> Whether to dispose the child after removing it. </param>
            ///<returns> True if the child was removed, false otherwise. </returns>
            public bool RemoveChild(Tree<T> child, bool disposeChild = true) {
                try {
                    _children.Remove(child);
                    child._parent = null;
                    if(disposeChild) child.Dispose();

                    return true;
                }
                catch (Exception) {
                    return false;
                }
            }

            ///<summary> Removes a child from the tree. </summary>
            ///<param name="index"> The index of the child to be removed. </param>
            ///<param name="disposeChild"> Whether to dispose the child after removing it. </param>
            ///<returns> True if the child was removed, false otherwise. </returns>
            public bool RemoveChild(int index, bool disposeChild = true) {
                try {
                    Tree<T> child = _children[index];

                    if(child == null) return false;

                    _children.RemoveAt(index);

                    child._parent = null;
                    if(disposeChild) child.Dispose();

                    return true;
                }
                catch (Exception) {
                    return false;
                }
            }

            ///<summary> Removes all children from the tree. </summary>
            ///<param name="disposeChildren"> Whether to dispose the children after removing them. </param>
            ///<returns> True if the children were removed, false otherwise. </returns>
            public bool RemoveChildren(bool disposeChildren = true) {
                try {
                    foreach (var child in _children) {
                        child._parent = null;
                        if(disposeChildren) child.Dispose();
                    }
                    _children.Clear();
                    return true;
                }
                catch (Exception) {
                    return false;
                }
            }

            ///<summary> Depth-first traversal of the tree. </summary>
            ///<param name="visit"> The action to be performed on each node. </param>
            public void DepthFirstTraverse(Action<Tree<T>> visit) {
                visit(this);

                foreach (var child in _children) 
                    child.DepthFirstTraverse(visit);
            }

            ///<summary> Breadth-first traversal of the tree. </summary>
            ///<param name="visit"> The action to be performed on each node. </param>
            public void BreadthFirstTraverse(Action<Tree<T>> visit) {
                Queue<Tree<T>> queue = new();
                queue.Enqueue(this);
                while (queue.Count > 0) {
                    var current = queue.Dequeue();
                    visit(current);
                    foreach (var child in current._children)
                        queue.Enqueue(child);
                }
            }

            ///<summary> Finds the first node that matches the given condition. </summary>
            ///<param name="match"> The condition to be matched. When the function returns true, the search stops. </param>
            ///<returns> The first node that matches the condition, or null if no node matches the condition. </returns>
            public Tree<T>? FindFirst(Func<T, bool> match) {
                if (match(_value))
                    return this;

                foreach (var child in _children) {
                    var found = child.FindFirst(match);
                    if (found != null) return found;
                }

                return null;
            }

            ///<summary> Finds all nodes that match the given condition. </summary>
            ///<param name="match"> The condition to be matched. </param>
            ///<returns> A list of all nodes that match the condition. </returns>
            public List<Tree<T>> FindAll(Func<T, bool> match) {
                List<Tree<T>> result = [];
                if (match(_value)) result.Add(this);
                foreach (var child in _children) {
                    var found = child.FindAll(match);
                    result.AddRange(found);
                }
                return result;
            }

            ///<summary> Removes the first node that matches the given condition. </summary>
            ///<param name="match"> The condition to be matched. When the function returns true, the search stops. </param>
            ///<returns> True if a node was removed, false otherwise. </returns>
            public bool RemoveFirst(Func<T, bool> match) {
                var node = FindFirst(match);
                if (node == null) return false;

                node.Dispose();

                return true;
            }

            ///<summary> Serializes the tree to a byte array using jsonSerializer. </summary>
            ///<returns> The serialized tree. </returns>
            public byte[] Serialize() {
                var options = new JsonSerializerOptions{
                    WriteIndented = false,
                    ReferenceHandler = ReferenceHandler.IgnoreCycles
                };

                return JsonSerializer.SerializeToUtf8Bytes(this, options);
            }

            ///<summary> Dispose the tree and all its children. </summary>
            public void Dispose() {   
                foreach (var c in _children) c.Dispose();

                _children.Clear();
                _value = default!;
                _parent = null;
            }

            ///<summary> Returns the tree children Enumerator. </summary>
            ///<returns> The tree children Enumerator. </returns>
            public IEnumerator<Tree<T>> GetEnumerator() {
                return _children.GetEnumerator();
            }

            ///<summary> Returns the tree children Enumerator. </summary>
            IEnumerator IEnumerable.GetEnumerator() {
                return GetEnumerator();
            }

        #endregion

        #region Static methods

            ///<summary> Deserializes a tree from a byte array using jsonSerializer. </summary>
            ///<param name="data"> The byte array to be deserialized. </param>
            ///<returns> The deserialized tree. </returns>
            public Tree<T>? Deserialize(byte[] data) {
                var options = new JsonSerializerOptions{
                    WriteIndented = false,
                    ReferenceHandler = ReferenceHandler.IgnoreCycles
                };

                return JsonSerializer.Deserialize<Tree<T>>(data, options);
            }

        #endregion
    }
}
