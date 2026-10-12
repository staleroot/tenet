"""
Map database addresses onto the most precise pseudocode expression.

The hard part of synchronizing a trace with Hex-Rays pseudocode is not the
navigation: it is deciding *what* to highlight. A single instruction can
correspond to

* a whole statement (``cinsn``),
* a sub-expression of that statement (``cexpr``), or
* -- when the decompiler merged / optimized things away -- to nothing that
  has an address of its own at all.

This module models that decision as data (``PseudoItem``) plus a pure
selection function (``PseudoMap.lookup``) so the rules can be reasoned
about and unit tested without a live decompiler. The IDA side
(``tenet.sync.hexrays_api``) is responsible for *harvesting* the items and
feeding them in.

Precision levels, best first:

``PRECISION_EXPR``
    the deepest expression whose ``ea`` is exactly the target address.
``PRECISION_ITEM``
    some other (shallower) ctree item at exactly the target address.
``PRECISION_LINE``
    the decompiled line that renders the target address: the item is
    known, but not which column of the line it starts at (this happens
    when the decompiler declines to give item coordinates).
``PRECISION_NEAREST``
    the closest addressable item in the same function -- an approximation,
    flagged as such so the UI can present it honestly.
``PRECISION_NONE``
    nothing maps to the address: **never** highlight anything.
"""

import bisect

PRECISION_EXPR = "expr"
PRECISION_ITEM = "item"
PRECISION_LINE = "line"
PRECISION_NEAREST = "nearest"
PRECISION_NONE = "none"

#: every precision level, best (most exact) first. Handy for ranking two
#: results, for assertions, and for the UI's "how sure are we" label.
PRECISION_ORDER = (
    PRECISION_EXPR,
    PRECISION_ITEM,
    PRECISION_LINE,
    PRECISION_NEAREST,
    PRECISION_NONE,
)

#: how far (in bytes of address distance) a 'nearest' fallback may stray
NEAREST_MAX_DISTANCE = 0x4000


class PseudoItem(object):
    """
    One addressable thing in a decompilation.

    Purely informational: it describes *what* the item is and *where* it
    renders, never how to render it.
    """

    __slots__ = ("ea", "line", "x", "length", "order", "is_expr", "op_name",
                 "has_coords")

    def __init__(self, ea, line, x, length=1, order=0, is_expr=True,
                 op_name="", has_coords=True):
        #: database address this item was produced from
        self.ea = ea
        #: 0-based line index inside the pseudocode widget
        self.line = line
        #: 0-based column the item starts at
        self.x = x
        #: approximate number of columns the item spans
        self.length = max(1, length)
        #: emission order within the line; later == more deeply nested
        #: (see tenet.sync.lexer for why this stands in for tree depth)
        self.order = order
        #: True for ``cexpr``-like items, False for statements / citems
        self.is_expr = is_expr
        #: the decompiler op name (``cot_add``, ``cit_if``, ...) if known
        self.op_name = op_name
        #: False when only the line is known (no usable column information)
        self.has_coords = has_coords

    @property
    def precision(self):
        if not self.has_coords:
            return PRECISION_LINE
        if self.is_expr:
            return PRECISION_EXPR
        return PRECISION_ITEM

    def __repr__(self):
        return (f"PseudoItem(ea=0x{self.ea:X}, line={self.line}, x={self.x}, "
                f"len={self.length}, order={self.order}, expr={self.is_expr}, "
                f"coords={self.has_coords}, op={self.op_name!r})")


class LookupResult(object):
    """The outcome of mapping an address onto the pseudocode."""

    def __init__(self, precision, item=None, line=None):
        self.precision = precision
        #: the winning item (None for PRECISION_LINE / PRECISION_NONE)
        self.item = item
        #: the line to place the cursor on
        self.line = line

    @property
    def found(self):
        return self.precision != PRECISION_NONE

    @property
    def exact(self):
        """
        True when the address maps onto an item with that exact ea.

        ``PRECISION_LINE`` counts: the address is certain, only the column
        within the line is not.
        """
        return self.precision in (PRECISION_EXPR, PRECISION_ITEM,
                                  PRECISION_LINE)

    def __repr__(self):
        return (f"LookupResult({self.precision!r}, item={self.item!r}, "
                f"line={self.line})")


class PseudoMap(object):
    """
    An address -> pseudocode item index for one decompiled function.

    Items may be added in any order; the map is finalized implicitly on
    first lookup.
    """

    def __init__(self, entry_ea=None):
        #: the entry address of the decompiled function (if known)
        self.entry_ea = entry_ea
        #: every harvested item, in harvest order
        self.items = []
        #: {ea: [items]} built lazily on first lookup
        self._by_ea = None

    #-- construction ----------------------------------------------------

    def add(self, item):
        """Register one addressable item."""
        self.items.append(item)
        self._by_ea = None

    def __len__(self):
        return len(self.items)

    def _finalize(self):
        """Index items by address."""
        if self._by_ea is not None:
            return
        by_ea = {}
        for item in self.items:
            by_ea.setdefault(item.ea, []).append(item)
        self._by_ea = by_ea

    #-- queries ---------------------------------------------------------

    def items_at(self, ea):
        """Return every item whose ``ea`` is exactly ``ea``."""
        self._finalize()
        return list(self._by_ea.get(ea, ()))

    def lookup(self, ea, max_distance=NEAREST_MAX_DISTANCE):
        """
        Map ``ea`` onto the most precise pseudocode position available.

        The fallback hierarchy is (best first):

        1. the innermost *expression* at exactly ``ea``,
        2. any other item at exactly ``ea`` (a statement, say),
        3. an item at exactly ``ea`` whose column is unknown -- the line is
           known, so only the line can be highlighted,
        4. the nearest item, when it is close enough to be trustworthy,
        5. nothing at all (``PRECISION_NONE``) -- the caller must then leave
           the pseudocode alone rather than highlight a guess.
        """
        exact = self.items_at(ea)

        # items that know where on their line they start
        with_coords = [item for item in exact if item.has_coords]

        # 1. innermost expression at this address (latest in preorder)
        exprs = [item for item in with_coords if item.is_expr]
        if exprs:
            best = max(exprs, key=lambda item: item.order)
            return LookupResult(PRECISION_EXPR, best, best.line)

        # 2. any other item at this address (a statement, say)
        if with_coords:
            best = max(with_coords, key=lambda item: item.order)
            return LookupResult(PRECISION_ITEM, best, best.line)

        # 3. the address renders, but no column information: line only
        if exact:
            best = max(exact, key=lambda item: item.order)
            return LookupResult(PRECISION_LINE, best, best.line)

        # 4. closest addressable item in this function
        nearest = self.nearest(ea, max_distance=max_distance)
        if nearest is not None:
            distance = abs(nearest.ea - ea)
            if distance <= max_distance:
                return LookupResult(PRECISION_NEAREST, nearest, nearest.line)

        # 5. nothing
        return LookupResult(PRECISION_NONE, None, None)

    def nearest(self, ea, max_distance=NEAREST_MAX_DISTANCE):
        """Return the item with the closest ``ea`` (or None)."""
        self._finalize()
        if not self._by_ea:
            return None

        eas = sorted(self._by_ea.keys())
        pos = bisect.bisect_left(eas, ea)

        best = None
        best_distance = None

        for candidate_pos in (pos - 1, pos):
            if not 0 <= candidate_pos < len(eas):
                continue
            candidate_ea = eas[candidate_pos]
            distance = abs(candidate_ea - ea)
            if best_distance is not None and distance >= best_distance:
                continue
            candidates = self._by_ea.get(candidate_ea)
            if candidates:
                best, best_distance = candidates[0], distance

        if best is None or best_distance is None or best_distance > max_distance:
            return None
        return best

    def mapped_addresses(self):
        """Return the sorted, distinct addresses covered by this map."""
        self._finalize()
        return sorted(self._by_ea.keys())


def merge_maps(base, extra):
    """
    Return a new :class:`PseudoMap` holding the items of both maps.

    Useful when a decompilation is refreshed (or when several widgets show
    the same function): an item in ``extra`` replaces any item of ``base``
    that renders at the same place, so the newer map wins.
    """
    merged = PseudoMap(entry_ea=base.entry_ea if base else None)

    # key -> position in merged.items; later additions overwrite earlier ones
    seen = {}

    for source in (base, extra):
        if not source:
            continue
        for item in source.items:
            key = (item.ea, item.line, item.x, item.order)
            existing = seen.get(key)
            if existing is None:
                seen[key] = len(merged.items)
                merged.add(item)
            else:
                merged.items[existing] = item

    # adding invalidates the address index; force a rebuild
    merged._by_ea = None
    return merged
