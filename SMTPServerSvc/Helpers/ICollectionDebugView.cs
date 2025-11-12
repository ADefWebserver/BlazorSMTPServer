using System;
using System.Collections.Generic;
using System.Linq;

namespace System.Collections.Generic
{
    // Helper debug-view compatible wrapper to support the requested expression
    // NOTE: This is intentionally named to match the debugger-view type name
    // so that the expression compiles while remaining safe and portable.
    internal sealed class ICollectionDebugView<T>
    {
        private readonly IEnumerable<T> _collection;

        public ICollectionDebugView(IEnumerable<T> collection)
        {
            _collection = collection ?? throw new ArgumentNullException(nameof(collection));
        }

        public IList<T> Items => _collection as IList<T> ?? _collection.ToList();
    }
}
