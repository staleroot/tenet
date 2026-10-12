"""
Bounded caches, staleness tokens and prefetch planning for FRINET sync.

Everything in this module is **pure Python**: no IDA, no Qt. The IDA / GUI
sides consume it (see ``tenet.sync.controller``), and it is unit tested
head-less (see ``tests/test_frinet_sync.py``).
"""

import collections


# maximum number of decompiled functions held at once
DEFAULT_DECOMPILE_CACHE_SIZE = 32

# maximum number of ctree maps held at once
DEFAULT_MAP_CACHE_SIZE = 32

# how many idxs around the current one are considered for prefetch
DEFAULT_PREFETCH_BUDGET = 24


class Generation(object):
    """
    A monotonically increasing 'generation' token.

    Used to reject results that were computed for an older state of the
    world (the user seeked again, or the trace was replaced) by the time an
    expensive operation such as a decompilation came back.
    """

    def __init__(self, value=0):
        self._value = value

    @property
    def value(self):
        return self._value

    def bump(self):
        """Invalidate every token handed out so far."""
        self._value += 1
        return self._value

    def current(self):
        """Return a token that identifies the current generation."""
        return self._value

    def is_current(self, token):
        """Return True when ``token`` still describes the current state."""
        return token == self._value


class LRUCache(object):
    """
    A tiny bounded least-recently-used cache.

    ``get()`` marks an entry as most-recently-used; a miss never inserts.
    """

    def __init__(self, max_entries):
        assert max_entries > 0, "an LRU cache must hold at least one entry"
        self.max_entries = max_entries
        self._data = collections.OrderedDict()

    def __len__(self):
        return len(self._data)

    def __contains__(self, key):
        return key in self._data

    def __bool__(self):
        return bool(self._data)

    # python2 compatibility (the plugin still supports older IDA builds)
    __nonzero__ = __bool__

    def get(self, key, default=None):
        """Return a cached value (marking it most-recently-used)."""
        try:
            value = self._data.pop(key)
        except KeyError:
            return default
        self._data[key] = value
        return value

    def peek(self, key, default=None):
        """Return a cached value *without* touching the recency order."""
        return self._data.get(key, default)

    def put(self, key, value):
        """Insert (or replace) a value, evicting the least recently used."""
        if key in self._data:
            self._data.pop(key)
        self._data[key] = value

        while len(self._data) > self.max_entries:
            self._data.popitem(last=False)

    def pop(self, key, default=None):
        """Remove and return a cached value."""
        return self._data.pop(key, default)

    def clear(self):
        """Drop every cached entry."""
        self._data.clear()

    def keys(self):
        """Return the cached keys, most recently used last."""
        return list(self._data.keys())


class DecompileCache(object):
    """
    Bounded caches for decompiled functions and their ctree maps.

    Both are keyed by the function entry address. They are kept separate
    because a ctree map is only useful to us while its pseudocode widget is
    alive, whereas the cfunc itself stays valid for the session.
    """

    def __init__(self, decompile_size=DEFAULT_DECOMPILE_CACHE_SIZE,
                 map_size=DEFAULT_MAP_CACHE_SIZE):
        self.cfuncs = LRUCache(decompile_size)
        self.maps = LRUCache(map_size)

    def get_cfunc(self, entry_ea):
        return self.cfuncs.get(entry_ea)

    def put_cfunc(self, entry_ea, cfunc):
        self.cfuncs.put(entry_ea, cfunc)

    def get_map(self, entry_ea):
        return self.maps.get(entry_ea)

    def put_map(self, entry_ea, pmap):
        self.maps.put(entry_ea, pmap)

    def invalidate(self, entry_ea=None):
        """Forget one function (or everything when no key is given)."""
        if entry_ea is None:
            self.cfuncs.clear()
            self.maps.clear()
            return
        self.cfuncs.pop(entry_ea, None)
        self.maps.pop(entry_ea, None)

    def clear(self):
        self.invalidate(None)


def plan_prefetch(center_idx, mapped_idxs, budget=DEFAULT_PREFETCH_BUDGET):
    """
    Pick the trace indexes worth prefetching around ``center_idx``.

    ``mapped_idxs`` is a sorted sequence of indexes whose events can be
    mapped into the database (events without an offset are never worth
    prefetching: there is nothing to highlight for them).

    The result is deduplicated, ordered by proximity to ``center_idx``
    (nearest first, alternating forward / backward) and truncated to
    ``budget`` entries. ``center_idx`` itself is never included.
    """
    if not mapped_idxs or budget <= 0:
        return []

    idxs = sorted(set(mapped_idxs))
    center = center_idx

    # index of the first entry >= center
    lo = 0
    hi = len(idxs)
    while lo < hi:
        mid = (lo + hi) // 2
        if idxs[mid] < center:
            lo = mid + 1
        else:
            hi = mid

    candidates = []
    before, after = lo - 1, lo

    #
    # walk outwards from the center, nearest first, alternating direction.
    # the center itself is skipped *while counting* so it cannot consume
    # part of the budget.
    #
    while len(candidates) < budget and (before >= 0 or after < len(idxs)):
        if after < len(idxs):
            if idxs[after] != center:
                candidates.append(idxs[after])
            after += 1
            if len(candidates) >= budget:
                break
        if before >= 0:
            if idxs[before] != center:
                candidates.append(idxs[before])
            before -= 1

    # the center can still appear twice when it is itself in mapped_idxs
    seen = set()
    ordered = []
    for idx in candidates:
        if idx == center or idx in seen:
            continue
        seen.add(idx)
        ordered.append(idx)

    return ordered[:budget]
