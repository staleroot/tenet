"""
FRINET trace <-> pseudocode synchronisation.

Layered so that each part can be reasoned about (and tested) on its own:

``tenet.sync.lexer``
    Pure lexing of IDA's color-tagged text: the hidden ``COLOR_ADDR``
    tokens that Hex-Rays embeds in its output, and the nesting order of
    each tagged span.

``tenet.sync.pseudomap``
    Pure mapping from a database address onto the most precise rendered
    expression, with an explicit five-level fallback hierarchy.

``tenet.sync.cache``
    Bounded LRU caches, generation tokens for staleness, and the prefetch
    planner.

``tenet.sync.navigation``
    History, bookmarks and an occurrence index for secondary navigation.

``tenet.sync.hexrays_api``
    The only module that imports Hex-Rays: harvesting ctree items, finding
    / opening pseudocode widgets, and moving the cursor.

``tenet.sync.controller``
    The orchestrator: coalesced, cache-backed, stale-rejecting updates
    driven by trace index changes.
"""

from .cache import (          # noqa: F401
    DecompileCache,
    Generation,
    LRUCache,
    plan_prefetch,
)
from .navigation import (     # noqa: F401
    Bookmarks,
    History,
    OccurrenceIndex,
)
from .pseudomap import (      # noqa: F401
    LookupResult,
    PRECISION_EXPR,
    PRECISION_ITEM,
    PRECISION_LINE,
    PRECISION_NEAREST,
    PRECISION_NONE,
    PseudoItem,
    PseudoMap,
)
from .lexer import (          # noqa: F401
    TaggedSpan,
    lex_tagged_line,
    strip_tags,
)
from .controller import (     # noqa: F401
    NullScheduler,
    PseudocodeSyncController,
    SyncEvent,
)
