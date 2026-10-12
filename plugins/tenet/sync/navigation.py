"""
Navigation aids layered on top of the trace reader.

Pure Python (no IDA / Qt) so the behaviour can be unit tested:

* :class:`History` -- back / forward through visited trace positions,
* :class:`Bookmarks` -- user-defined named positions,
* :class:`OccurrenceIndex` -- every idx at which a given address (or
  module offset) was executed, for 'next / previous occurrence' style
  navigation without scanning the whole trace each time.
"""

import bisect

DEFAULT_HISTORY_SIZE = 128


class History(object):
    """
    A bounded back/forward history of trace positions.

    Positions are opaque values (typically trace indexes). Moving to a new
    position clears the forward stack, exactly like a browser.
    """

    def __init__(self, max_entries=DEFAULT_HISTORY_SIZE):
        self.max_entries = max_entries
        self._entries = []
        self._cursor = -1

    def __len__(self):
        return len(self._entries)

    @property
    def current(self):
        if not 0 <= self._cursor < len(self._entries):
            return None
        return self._entries[self._cursor]

    @property
    def can_go_back(self):
        return self._cursor > 0

    @property
    def can_go_forward(self):
        return self._cursor < len(self._entries) - 1

    def record(self, position):
        """
        Record a visit to ``position``.

        Returns True when the history actually changed (re-visiting the
        current position is a no-op).
        """
        if position is None:
            return False

        # already there: nothing to record
        if self.current == position:
            return False

        # a fresh visit invalidates the forward stack
        del self._entries[self._cursor + 1:]
        self._entries.append(position)
        self._cursor = len(self._entries) - 1

        # enforce the bound, dropping the oldest entry
        overflow = len(self._entries) - self.max_entries
        if overflow > 0:
            del self._entries[:overflow]
            self._cursor -= overflow

        return True

    def back(self):
        """Step back one entry (returns the position, or None)."""
        if not self.can_go_back:
            return None
        self._cursor -= 1
        return self.current

    def forward(self):
        """Step forward one entry (returns the position, or None)."""
        if not self.can_go_forward:
            return None
        self._cursor += 1
        return self.current

    def reset(self):
        """Forget everything."""
        self._entries = []
        self._cursor = -1


class Bookmarks(object):
    """
    Named trace positions the user can return to.

    Stored as ``{name: position}`` with a stable, sorted listing.
    """

    def __init__(self):
        self._bookmarks = {}

    def __len__(self):
        return len(self._bookmarks)

    def __contains__(self, name):
        return name in self._bookmarks

    def names(self):
        """Return the bookmark names, sorted."""
        return sorted(self._bookmarks.keys())

    def items(self):
        """Return ``(name, position)`` pairs, sorted by name."""
        return sorted(self._bookmarks.items(), key=lambda kv: kv[0])

    def add(self, name, position):
        """Create or move a bookmark."""
        if not name:
            raise ValueError("a bookmark needs a name")
        if position is None:
            raise ValueError("a bookmark needs a position")
        self._bookmarks[name] = position

    def get(self, name, default=None):
        return self._bookmarks.get(name, default)

    def remove(self, name):
        """Delete a bookmark. Returns True when one was removed."""
        return self._bookmarks.pop(name, None) is not None

    def clear(self):
        self._bookmarks.clear()


class OccurrenceIndex(object):
    """
    Index the trace indexes at which each address / offset occurred.

    The trace reader can already search for the next execution of an
    address, but doing so scans the trace. This index is built once (in a
    single pass over the unique addresses) and then answers
    next/previous-occurrence queries with a binary search.

    Both keys are supported so navigation works whether the caller thinks
    in database addresses (``ea``) or in module offsets (``off``): events
    without an offset are simply absent from the offset index.
    """

    def __init__(self):
        #: {address: [idx, ...]} in ascending order
        self._by_ea = {}
        #: {offset: [idx, ...]} in ascending order
        self._by_off = {}
        #: True when build() stopped early to stay responsive
        self.truncated = False

    #-- construction ----------------------------------------------------

    def add(self, ea, idx, off=None):
        """Record one event. ``off`` may be None (external / legacy)."""
        if ea is not None:
            self._by_ea.setdefault(ea, []).append(idx)
        if off is not None:
            self._by_off.setdefault(off, []).append(idx)

    @classmethod
    def build(cls, reader, max_events=None):
        """
        Build an index by walking the trace once.

        ``max_events`` bounds the work for enormous traces; when hit, the
        index only covers the beginning of the trace (and says so via
        ``truncated``).
        """
        index = cls()
        length = reader.trace.length
        if max_events is not None:
            length = min(length, max_events)

        for idx in range(length):
            try:
                ea = reader.analysis.rebase_pointer(reader.get_ip(idx))
                off = reader.get_offset(idx)
            except Exception:
                continue
            index.add(ea, idx, off)

        index.truncated = (max_events is not None and
                           max_events < reader.trace.length)
        return index

    #-- queries ---------------------------------------------------------

    def occurrences(self, key):
        """
        Return every idx at which ``key`` was executed.

        ``key`` may be a database address or a module offset. In the
        (unlikely) case the same integer means both, the address wins: it is
        the primary navigation key.
        """
        idxs = self._by_ea.get(key)
        if idxs is None:
            idxs = self._by_off.get(key, [])
        return list(idxs)

    def has(self, key):
        return key in self._by_ea or key in self._by_off

    def next_occurrence(self, key, idx, inclusive=False):
        """
        Return the first occurrence after ``idx`` (or None).

        With ``inclusive=True`` an occurrence *at* ``idx`` also counts,
        which is what a 'repeat current' action wants.
        """
        idxs = self.occurrences(key)
        if not idxs:
            return None
        offset = bisect.bisect_left(idxs, idx) if inclusive \
            else bisect.bisect_right(idxs, idx)
        if offset >= len(idxs):
            return None
        return idxs[offset]

    def prev_occurrence(self, key, idx, inclusive=False):
        """
        Return the last occurrence before ``idx`` (or None).
        """
        idxs = self.occurrences(key)
        if not idxs:
            return None
        offset = bisect.bisect_right(idxs, idx) if inclusive \
            else bisect.bisect_left(idxs, idx)
        if offset <= 0:
            return None
        return idxs[offset - 1]

    def count(self, key):
        return len(self.occurrences(key))

    def clear(self):
        self._by_ea = {}
        self._by_off = {}
        self.truncated = False

    @property
    def size(self):
        """Number of distinct indexed addresses."""
        return len(self._by_ea)
