"""
Lexer for IDA's color-tagged text (the pseudocode strings).

Hex-Rays tags the ctree items in its output with hidden address tokens, so
the *rendered* text already contains everything needed to map text columns
back onto ctree items. The layout is defined in ``lines.hpp``:

* ``COLOR_ON  == 0x01`` followed by one *color* byte starts a styled span,
* ``COLOR_OFF == 0x02`` followed by the same color byte ends it,
* ``COLOR_ESC == 0x03`` quotes the next byte so ``0x01``/``0x02``/``0x03``
  can appear as literal text,
* ``COLOR_ADDR == 0x28`` is a *fictive* color that occupies the color-byte
  slot of a ``COLOR_ON``: the token is ``COLOR_ON COLOR_ADDR`` followed by
  ``COLOR_ADDR_SIZE`` hex digits (16 on 64-bit) encoding a ctree item
  index. Per the SDK it has **no** ``COLOR_OFF`` pair.

So one line looks like::

    COLOR_ON COLOR_ADDR <hex> COLOR_ON COLOR_KEYWORD "if" COLOR_OFF ...

Ground truth for the address token is the ``lex_citem_indexes()`` helper
that ships with Tenet (``integration/api/ida_api.py``), which reads exactly
``COLOR_ON COLOR_ADDR <hex>``.

Depth, and why it is an *order* rather than a tree walk
-------------------------------------------------------
Hex-Rays emits the ctree items of a line in **preorder**: an item is
printed before the items nested inside it. Among the tokens that render at
the same address, the one printed last is therefore the innermost -- an
operand rather than the statement that contains it.

That is exactly the precision FRINET highlights with, and it costs no ctree
walk (which would mean reimplementing one accessor per ``cot_*``/``cit_*``
opcode). ``TaggedSpan.order`` is the ordinal of a token among the address
tokens of its line; :class:`~tenet.sync.pseudomap.PseudoMap` uses it to rank
the items that share an address (the latest one wins).

What this cannot do: order two items at the same address that render on
*different* lines. The length reported is the distance to the next address
token (or to the end of the line), which is an approximation of the item's
extent -- good enough to place a cursor, and documented as such.

This module is deliberately pure Python: it is exercised by unit tests with
synthetic tagged strings, and only the harvesting side (``hexrays_api``)
talks to a live decompiler.
"""

import re

# color tag bytes (see idasdk/lines.hpp)
COLOR_ON = 0x01
COLOR_OFF = 0x02
COLOR_ESC = 0x03
COLOR_ADDR = 0x28

#: number of hex digits following a COLOR_ADDR token; 8 on 32-bit, 16 on 64-bit
DEFAULT_ADDR_SIZE = 16

_HEX = re.compile(r"^[0-9A-Fa-f]+$")


class TaggedSpan(object):
    """
    One addressable (tagged) span of rendered text.

    ``order`` is the ordinal of this token among the address tokens of its
    line. Hex-Rays prints a ctree in preorder, so a *later* token at the
    same address is nested more deeply inside the earlier one.
    """

    __slots__ = ("index", "x", "length", "order")

    def __init__(self, index, x, length, order=0):
        #: ctree item index (the number encoded in the COLOR_ADDR token)
        self.index = index
        #: visible column the span starts at (0-based); exact
        self.x = x
        #: approximate visible extent, in characters (see module docstring)
        self.length = max(1, length)
        #: ordinal of this token among the address tokens of its line
        self.order = order

    def __repr__(self):
        return (f"TaggedSpan(index={self.index}, x={self.x}, "
                f"length={self.length}, order={self.order})")

    def __eq__(self, other):
        if not isinstance(other, TaggedSpan):
            return NotImplemented
        return (self.index, self.x, self.length, self.order) == \
               (other.index, other.x, other.length, other.order)

    def __hash__(self):
        return hash((self.index, self.x, self.length, self.order))


def _skip_addr_payload(line, start, addr_size):
    """
    Return the position just past a ``COLOR_ADDR`` payload starting at ``start``.

    A well-formed payload is exactly ``addr_size`` hex digits. A *truncated*
    one (a line clipped mid-token) ends earlier -- at the next tag byte, or
    at the end of the text. The caller must resume lexing exactly there:
    swallowing ``addr_size`` bytes blindly would eat the tokens that follow
    the truncated one, turning one clipped token into a lost line.
    """
    end = min(start + addr_size, len(line))

    for pos in range(start, end):
        # 0x01..0x03: COLOR_ON / COLOR_OFF / COLOR_ESC terminate the payload
        if ord(line[pos]) <= COLOR_ESC:
            return pos

    return end


def strip_tags(line, addr_size=DEFAULT_ADDR_SIZE):
    """
    Return ``line`` with every color tag (and its payload) removed.

    Used to compute the text the user actually sees, so the columns we
    report line up with what the pseudocode widget renders.
    """
    return "".join(_visible(line, addr_size))


def _visible(line, addr_size):
    """Yield the visible characters of a tagged line."""
    i = 0
    length = len(line)

    while i < length:
        byte = ord(line[i])

        # escape: the quoted byte is literal text
        if byte == COLOR_ESC:
            if i + 1 < length:
                yield line[i + 1]
            i += 2
            continue

        # styled span: skip the tag and its color byte
        if byte == COLOR_ON:
            # an address token hides in the color-byte slot
            if i + 1 < length and ord(line[i + 1]) == COLOR_ADDR:
                i = _skip_addr_payload(line, i + 2, addr_size)
                continue
            i += 2
            continue

        if byte == COLOR_OFF:
            i += 2
            continue

        # a bare 0x28 is the character '(', not a tag: only COLOR_ON's
        # color-byte slot carries a COLOR_ADDR (handled above)
        yield line[i]
        i += 1


def lex_tagged_line(line, addr_size=DEFAULT_ADDR_SIZE):
    """
    Lex the addressable spans of one tagged line.

    Returns a list of :class:`TaggedSpan`, ordered by start column (ties
    broken outermost first). Spans carrying no address token -- a keyword,
    a register name -- are not reported: they have no ctree identity.

    Malformed tags never raise: a truncated address payload or an
    unbalanced ``COLOR_OFF`` simply loses that one token, because a quirk of
    the decompiler's renderer must not take the whole plugin down.
    """
    spans = []

    # (index, visible_x) of each address token, in emission order
    marks = []

    i = 0
    length = len(line)
    visible_x = 0

    def emit(index, start_x, end_x, ordinal):
        spans.append(TaggedSpan(index, start_x, max(1, end_x - start_x),
                                ordinal))

    while i < length:
        byte = ord(line[i])

        # -- escape: the quoted byte is literal text ----------------------
        if byte == COLOR_ESC:
            if i + 1 < length:
                visible_x += 1
            i += 2
            continue

        # -- COLOR_ON, possibly carrying a hidden address token -----------
        if byte == COLOR_ON:
            if i + 1 < length and ord(line[i + 1]) == COLOR_ADDR:
                i += 2
                end = _skip_addr_payload(line, i, addr_size)
                payload = line[i:end]
                i = end

                if len(payload) != addr_size or not _HEX.match(payload):
                    # truncated / non-hex payload: drop this token, but
                    # keep lexing the rest of the line
                    continue

                try:
                    index = int(payload, 16)
                except ValueError:
                    continue

                #
                # the span of the previous token ends where this one starts
                #
                if marks:
                    previous_index, previous_x = marks[-1]
                    emit(previous_index, previous_x, visible_x, len(marks) - 1)

                marks.append((index, visible_x))
                continue

            i += 2      # ordinary styled span: skip tag + color byte
            continue

        # -- COLOR_OFF: skip tag + color byte -----------------------------
        if byte == COLOR_OFF:
            i += 2
            continue

        # -- ordinary visible character -----------------------------------
        #
        # NOTE: a bare 0x28 is the character '(' (ASCII 40), NOT a COLOR_ADDR
        # tag: per requires_color_esc() only bytes 0x01..0x04 are escaped,
        # and COLOR_ADDR is only meaningful as the color byte that follows a
        # COLOR_ON. Treating it as a tag here would eat every parenthesis.
        #
        visible_x += 1
        i += 1

    # the last token on the line runs to the end of the visible text
    if marks:
        index, start_x = marks[-1]
        emit(index, start_x, visible_x, len(marks) - 1)

    spans.sort(key=lambda span: (span.x, span.order))
    return spans
