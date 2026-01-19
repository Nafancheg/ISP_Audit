using System;
using System.Collections.Generic;
using System.Linq;

namespace IspAudit.Bypass
{
    /// <summary>
    /// Потокобезопасный журнал последних транзакций применения обхода.
    /// P0.1 MVP: хранение in-memory для UI и экспорта.
    /// </summary>
    public sealed class BypassApplyTransactionJournal
    {
        private readonly object _sync = new();
        private readonly int _capacity;
        private readonly LinkedList<BypassApplyTransaction> _items = new();

        public BypassApplyTransactionJournal(int capacity)
        {
            if (capacity <= 0) throw new ArgumentOutOfRangeException(nameof(capacity));
            _capacity = capacity;
        }

        public void Add(BypassApplyTransaction transaction)
        {
            if (transaction == null) throw new ArgumentNullException(nameof(transaction));

            lock (_sync)
            {
                _items.AddFirst(transaction);
                while (_items.Count > _capacity)
                {
                    _items.RemoveLast();
                }
            }
        }

        public IReadOnlyList<BypassApplyTransaction> Snapshot()
        {
            lock (_sync)
            {
                return _items.ToList();
            }
        }

        public void Clear()
        {
            lock (_sync)
            {
                _items.Clear();
            }
        }
    }
}
