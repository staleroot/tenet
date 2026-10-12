"""
The one and only place FRINET touches Hex-Rays.

Everything here is written defensively: the decompiler may be absent, a
function may refuse to decompile, a widget may be closed mid-navigation.
Each entry point either returns something usable or ``None`` -- callers
never have to catch IDA-specific exceptions.

The expensive, easy-to-get-wrong part (mapping rendered text back onto
ctree items) lives in the pure :mod:`tenet.sync.lexer` /
:mod:`tenet.sync.pseudomap` modules so it can be tested without IDA; this
file is only the thin harvesting / navigation layer.
"""

import logging

from .lexer import lex_tagged_line, strip_tags
from .pseudomap import PseudoItem, PseudoMap

logger = logging.getLogger("Tenet.Sync.HexRays")

#
# diagnostics are optional: this module has to stay importable outside IDA
# (the tests drive it head-less), but inside IDA the output window is the
# only place anyone will actually look -- which is exactly where a swallowed
# navigation failure has to appear, or a sync that maps perfectly reads as
# "nothing happened".
#
try:
    from tenet.util.log import pdbg
except Exception:  # pragma: no cover - head-less test runs
    def pdbg(fmt, *args):
        return

# set once we have probed (and cached) decompiler availability
_available = None

#: never harvest more than this many items from a single decompilation;
#: absurdly large functions are not worth freezing the UI for
MAX_HARVEST_ITEMS = 20000


#-----------------------------------------------------------------------------
# Availability
#-----------------------------------------------------------------------------

def _ida_hexrays():
    """Import ida_hexrays (or None when the decompiler is not installed)."""
    try:
        import ida_hexrays
        return ida_hexrays
    except ImportError:
        return None


def is_available():
    """
    Return True when an IDA decompiler is loaded and usable.

    The result is cached: ``init_hexrays_plugin()`` is not free, and we ask
    on every navigation.
    """
    global _available
    if _available is not None:
        return _available

    ida_hexrays = _ida_hexrays()
    if ida_hexrays is None:
        _available = False
        return False

    try:
        _available = bool(ida_hexrays.init_hexrays_plugin())
    except Exception:
        logger.debug("init_hexrays_plugin() failed", exc_info=True)
        _available = False

    return _available


def reset_availability_cache():
    """Forget the cached availability (used by tests / after plugin unload)."""
    global _available
    _available = None


def decompiler_error_text(ea):
    """Return the decompiler's failure reason for an address (or '')."""
    ida_hexrays = _ida_hexrays()
    if ida_hexrays is None:
        return ""
    try:
        return str(getattr(ida_hexrays.cfunc_t, "failure", "") or "")
    except Exception:
        return ""


#-----------------------------------------------------------------------------
# Decompilation
#-----------------------------------------------------------------------------

def decompile(ea):
    """
    Decompile the function containing ``ea``.

    Returns the ``cfunc`` (or None). The caller owns nothing: the decompiler
    keeps the cfunc alive through its reference count.
    """
    if not is_available():
        return None

    ida_hexrays = _ida_hexrays()
    try:
        cfunc = ida_hexrays.decompile(ea)
    except Exception as exc:
        logger.debug("decompile(0x%X) failed: %s", ea, exc)
        return None

    if cfunc is None:
        logger.debug("decompile(0x%X) returned no cfunc", ea)
    return cfunc


def function_entry_ea(ea):
    """
    Return the entry address of the function containing ``ea`` (or None).

    Used as the cache key: two events inside the same function share one
    decompilation.
    """
    if not is_available():
        return None
    try:
        import ida_funcs
    except ImportError:
        return None

    try:
        func = ida_funcs.get_func(ea)
    except Exception:
        return None
    if not func:
        return None
    return func.start_ea


def function_name(ea):
    """
    Return the demangled (when possible) name of the function at ``ea``.

    Used only for display -- the event info panel labels the function a
    given address decompiled into. Returns None when Hex-Rays is absent,
    the address is not in a function, or the name cannot be resolved.
    """
    if not is_available():
        return None
    try:
        import ida_funcs
        import ida_name
    except ImportError:
        return None

    try:
        func = ida_funcs.get_func(ea)
        if not func:
            return None
        name = ida_funcs.get_func_name(func.start_ea)
        if not name:
            return None
        return ida_name.demangle_name(name) or name
    except Exception:
        return None


#-----------------------------------------------------------------------------
# Pseudocode widget registry
#-----------------------------------------------------------------------------
#
#    IDA offers no "list every open widget" API that returns decompiler
#    views, so we learn about pseudocode windows from the decompiler itself:
#    a Hexrays_Hooks subclass records every view it opens and forgets it
#    when it closes. Everything else (the current widget, a freshly opened
#    view) is folded into the same registry on demand.
#

_hooks = None
_open_vduis = []


class _PseudocodeHooks(object):
    """
    Track the set of open pseudocode views.

    Instantiated lazily; never raises into the decompiler.
    """

    def __init__(self):
        import ida_hexrays

        hooks = ida_hexrays.Hexrays_Hooks()
        hooks.open_pseudocode = self._on_open
        hooks.switch_pseudocode = self._on_switch
        hooks.close_pseudocode = self._on_close
        hooks.hook()
        self._hooks = hooks

    #-- hook handlers ---------------------------------------------------

    def _on_open(self, vu):
        _remember_vdui(vu)
        return 0

    def _on_switch(self, vu):
        # a view was reloaded with another function: it may show a different
        # entry now, so drop and re-add it
        _forget_vdui(vu)
        _remember_vdui(vu)
        return 0

    def _on_close(self, vu):
        _forget_vdui(vu)
        return 0

    #-- teardown --------------------------------------------------------

    def unhook(self):
        try:
            self._hooks.unhook()
        except Exception:
            logger.debug("unhook() failed", exc_info=True)


def _ensure_hooks():
    """Install the tracking hooks once (and only when the UI is present)."""
    global _hooks
    if _hooks is not None:
        return True
    if not is_available():
        return False
    try:
        _hooks = _PseudocodeHooks()
    except Exception:
        logger.debug("could not install pseudocode hooks", exc_info=True)
        _hooks = None
        return False
    return True


def _vdui_alive(vu):
    """True when a tracked vdui still refers to a real, valid view."""
    if vu is None:
        return False
    try:
        return bool(vu.valid())
    except Exception:
        return False


#: ceiling on tracked views. A guard for builds whose wrappers cannot be
#: compared at all: a long session must not grow the registry without bound
#: even if :func:`_same_view` degrades to plain identity comparison.
MAX_TRACKED_VIEWS = 32


def _same_view(a, b):
    """
    True when two values refer to the same pseudocode view.

    ``open_pseudocode()`` hands back a *fresh* ``vdui_t`` wrapper every time
    it is called, and the hooks receive yet another one, so ``is`` cannot see
    that they describe the same window. That is how the registry recorded one
    view once per retarget -- the log listed the same window eleven times.
    The widget is what stays constant across wrappers, so it is compared
    first; where this build offers nothing comparable the function degrades
    to the old identity test rather than wrongly merging two windows that
    happen to show the same function.
    """
    if a is b:
        return True

    for name in ("ct", "widget"):
        try:
            left = getattr(a, name, None)
            right = getattr(b, name, None)
        except Exception:
            continue
        if left is None or right is None:
            continue
        try:
            if left == right:
                return True
        except Exception:
            continue
    return False


def _remember_vdui(vu):
    if not _vdui_alive(vu):
        return
    for known in _open_vduis:
        if _same_view(known, vu):
            return
    if len(_open_vduis) >= MAX_TRACKED_VIEWS:
        del _open_vduis[0]
        logger.debug("tracked pseudocode views hit the %d entry ceiling",
                     MAX_TRACKED_VIEWS)
    _open_vduis.append(vu)


def _forget_vdui(vu):
    # every matching entry goes, not just the first: entries recorded before
    # _same_view learned to compare wrappers are all the same window
    for i in range(len(_open_vduis) - 1, -1, -1):
        if _same_view(_open_vduis[i], vu):
            del _open_vduis[i]


def iter_open_pseudocode():
    """
    Yield the currently open (and valid) pseudocode views.

    The current widget is always considered, then every view the hooks have
    seen open. Stale entries are pruned as they are encountered.
    """
    if not is_available():
        return

    import ida_hexrays
    import ida_kernwin

    #
    # identity comparison cannot be used here either: the current widget and
    # a tracked entry can be two wrappers of one view, and counting it twice
    # is what made a single window read as ten
    #
    seen = []

    # the widget the user is looking at right now
    try:
        widget = ida_kernwin.get_current_widget()
        vdui = ida_hexrays.get_widget_vdui(widget) if widget else None
    except Exception:
        vdui = None

    if _vdui_alive(vdui):
        seen.append(vdui)
        yield vdui

    # everything the hooks have recorded
    for i in range(len(_open_vduis) - 1, -1, -1):
        vu = _open_vduis[i]
        if not _vdui_alive(vu):
            del _open_vduis[i]
            continue
        if any(_same_view(vu, other) for other in seen):
            continue
        seen.append(vu)
        yield vu


def find_pseudocode_widget(ea=None):
    """
    Return the ``vdui`` of an already-open pseudocode widget.

    With ``ea`` given, only a view currently showing the function
    containing ``ea`` is accepted. Returns None when there is none -- this
    function never opens a window behind the user's back.
    """
    if not is_available():
        return None

    target_entry = function_entry_ea(ea) if ea is not None else None

    for vdui in iter_open_pseudocode():
        if target_entry is None:
            return vdui
        try:
            if vdui.cfunc and vdui.cfunc.entry_ea == target_entry:
                return vdui
        except Exception:
            continue

    return None


def ensure_widget_tracking():
    """
    Make sure open pseudocode views are being tracked.

    Called when a trace is attached, *not* lazily the first time a view is
    wanted -- which is the trap this function exists to avoid. The hooks can
    only see views opened after they are installed, so leaving installation
    to ``open_pseudocode_widget`` means a window the user opened before the
    trace (or opened while focused elsewhere) is invisible to
    :func:`iter_open_pseudocode`, and every sync reports
    ``no-pseudocode-widget`` for a view that is plainly on screen. The two
    failure modes are indistinguishable from outside, which is exactly why
    tracking has to start before anything is queried.
    """
    try:
        return _ensure_hooks()
    except Exception:
        logger.debug("could not install pseudocode hooks", exc_info=True)
        return False


def describe_open_pseudocode():
    """
    One short line naming every tracked pseudocode view, for diagnostics.

    Returns ``"(none)"`` when nothing is open. This is the fact a
    ``no-pseudocode-widget`` sync needs to disambiguate: "the decompiler was
    never opened" and "it is open on a different function" look identical
    from the caller's side, and the correct response to each is different.
    """
    if not is_available():
        return "(hex-rays unavailable)"

    parts = []
    for vdui in iter_open_pseudocode():
        entry = None
        try:
            entry = vdui.cfunc.entry_ea if vdui.cfunc else None
        except Exception:
            entry = None

        if entry is None:
            parts.append("(unknown)")
            continue

        name = None
        try:
            name = function_name(entry)
        except Exception:
            name = None
        if name:
            parts.append("0x%X(%s)" % (entry, name))
        else:
            parts.append("0x%X" % entry)

    return ", ".join(parts) if parts else "(none)"


def open_pseudocode_widget(ea):
    """
    Open (or reuse) a pseudocode widget showing the function at ``ea``.

    Returns the ``vdui``, or None when the function cannot be decompiled.

    ``OPF_REUSE`` means IDA reloads an existing window with the new function
    rather than spawning a second one, so a caller that wants a view to
    follow something around can call this for every location and end up with
    exactly one window instead of one per location. That is how pseudocode
    sync obtains a view: deliberately, once, when nothing already shows the
    function. It is never called on a hot path -- ``find_pseudocode_widget``
    answers first, and a function that will not decompile is remembered so
    the failure is not retried once per trace event.
    """
    if not is_available():
        return None

    import ida_hexrays

    # already showing the right function? reuse it
    existing = find_pseudocode_widget(ea)
    if existing is not None:
        return existing

    _ensure_hooks()

    #
    # NB: open_pseudocode() returns a vdui_t* directly (not a TWidget*), so
    # there is no second lookup through get_widget_vdui() here.
    #
    try:
        vdui = ida_hexrays.open_pseudocode(ea, ida_hexrays.OPF_REUSE)
    except Exception as exc:
        logger.debug("open_pseudocode(0x%X) failed: %s", ea, exc)
        return None

    if not vdui:
        return None

    _remember_vdui(vdui)
    return vdui


def shutdown_widget_registry():
    """Unhook and forget every tracked view (plugin unload / trace close)."""
    global _hooks
    if _hooks is not None:
        _hooks.unhook()
        _hooks = None
    del _open_vduis[:]
    # a fresh trace may want the navigation surface dumped again; the build
    # will not have changed, but the log is cheap and only printed on failure
    _surface_reported[0] = False
    _place_name_modules.clear()
    _constructible[0] = None


def is_widget_visible(vdui):
    """True when the given pseudocode widget is on screen and valid."""
    if vdui is None:
        return False
    try:
        return bool(vdui.visible() and vdui.valid())
    except Exception:
        return False


#-----------------------------------------------------------------------------
# Harvesting: cfunc -> PseudoMap
#-----------------------------------------------------------------------------

def build_pseudo_map(cfunc):
    """
    Build a :class:`PseudoMap` for a decompiled function.

    The map is built from the *rendered* pseudocode: every line is lexed for
    its hidden ``COLOR_ADDR`` tokens, and each token is resolved against
    ``cfunc.treeitems`` to learn the address, kind and nesting order of the
    item it renders. That is what lets FRINET highlight the operand (not the
    whole statement) when the trace proves the address of a sub-expression.

    Returns None when the decompilation cannot be read.
    """
    if cfunc is None:
        return None

    try:
        return _build_pseudo_map(cfunc)
    except Exception:
        # a decompilation shape we do not understand must not break the
        # timeline: fall back to "no pseudocode mapping" for this function
        logger.debug("build_pseudo_map() failed", exc_info=True)
        return None


def _build_pseudo_map(cfunc):
    pmap = PseudoMap(entry_ea=cfunc.entry_ea)

    try:
        lines = cfunc.get_pseudocode()
        treeitems = cfunc.treeitems
    except Exception:
        logger.debug("cfunc has no pseudocode/treeitems", exc_info=True)
        return pmap

    harvested = 0

    for line_number in range(lines.size()):

        line_text = lines[line_number].line

        for span in lex_tagged_line(line_text):

            if harvested >= MAX_HARVEST_ITEMS:
                logger.debug("harvest cap reached for 0x%X", cfunc.entry_ea)
                return pmap

            try:
                item = treeitems[span.index]
            except (IndexError, TypeError):
                continue

            ea = getattr(item, "ea", None)
            if ea is None or ea == 0xFFFFFFFFFFFFFFFF:
                continue

            try:
                is_expr = bool(item.is_expr())
            except Exception:
                is_expr = True

            op_name = _op_name(item)

            pmap.add(PseudoItem(
                ea=ea,
                line=line_number,
                x=span.x,
                length=span.length,
                order=span.order,
                is_expr=is_expr,
                op_name=op_name,
            ))
            harvested += 1

    return pmap


def _op_name(item):
    """Best-effort decompiler op name for an item ('' when unknown)."""
    for attribute in ("opname", "op"):
        try:
            value = getattr(item, attribute, None)
        except Exception:
            continue
        if isinstance(value, str) and value:
            return value
        # some builds expose op as an int enum whose name lives in the class
        try:
            name = getattr(value, "name", None)
            if isinstance(name, str) and name:
                return name
        except Exception:
            pass
    return ""


def pseudocode_line_text(vdui, line_number):
    """Return the *visible* text of one line of a pseudocode widget."""
    if vdui is None:
        return None
    try:
        lines = vdui.cfunc.get_pseudocode()
        return strip_tags(lines[line_number].line)
    except Exception:
        return None


#-----------------------------------------------------------------------------
# Navigation
#-----------------------------------------------------------------------------

def _view_handles(vdui, attempts):
    """
    Every candidate handle for a pseudocode view, whichever this build uses.

    IDA has called this thing different things across versions (``ct``,
    ``get_widget()``, ``widget``), and a wrong handle makes ``jumpto`` fail
    *silently*: it returns False instead of raising, which looks exactly
    like "that line does not exist". Trying each in turn turns one silent
    refusal into a log line naming the handle that worked.
    """
    found = []
    for name in ("ct", "get_widget", "widget"):
        value = getattr(vdui, name, None)
        if value is None:
            continue
        try:
            value = value() if callable(value) else value
        except Exception as exc:
            attempts.append("%s() raised %s: %s"
                            % (name, type(exc).__name__, exc))
            continue
        if value is not None:
            found.append((name, value))

    if not found:
        attempts.append("no view handle (ct / get_widget / widget all absent)")
    return found


#
# The place class the pseudocode viewer is proven to accept.
#
# Discovered at runtime, and deliberately never named here. The class that
# *looks* right -- simpleline_place_t -- is abstract on recent builds, so it
# cannot be constructed at all, and its concrete subclass differs between IDA
# versions. Naming it from this side already cost two rounds of guessing, so
# instead every *place_t this build can construct is offered to the viewer
# once, the winner is remembered, and every later jump goes straight to it.
#
_accepted_place_class = [None]

#: whether *any* place class can be built here -- None until checked. Where
#: every class is abstract the discovery fails identically on every trace
#: event, so it is answered once rather than re-noting the refusals forever.
_constructible = [None]

#: class name -> the module it was found in. The cache remembers the *name*
#: the viewer accepted, but a name imported from ``ida_hexrays`` does not
#: resolve on ``ida_kernwin`` -- without this a cache hit would report "not
#: callable" for a class that worked a moment ago, and only from the second
#: trace event onwards.
_place_name_modules = {}

#: set once the navigation surface has been dumped, so it appears in the log
#: exactly once rather than once per trace event
_surface_reported = [False]


def _note(attempts, message):
    """Record an attempt once -- the same refusal repeats per trace event."""
    if message not in attempts:
        attempts.append(message)


def _place_modules(ida_kernwin):
    """
    The modules worth scanning for a place class.

    ``ida_kernwin`` owns the generic ones, but the decompiler defines its own
    viewer, and a place built for the pseudocode widget is the only kind it
    is certain to accept -- so it is scanned too.
    """
    modules = [("ida_kernwin", ida_kernwin)]
    for name in ("ida_hexrays",):
        try:
            modules.append((name, __import__(name)))
        except Exception:
            continue
    return modules


def _discover_candidates(ida_kernwin):
    """Every place class this build exposes, de-duplicated by name."""
    candidates = []
    seen = set()
    for _module_name, module in _place_modules(ida_kernwin):
        for name in sorted(n for n in dir(module) if n.endswith("place_t")):
            if name in seen:
                continue
            seen.add(name)
            candidates.append((name, module))
    return candidates


def _cached_candidates(cached, ida_kernwin):
    """The remembered class, resolved back to the module that owns it."""
    module = _place_name_modules.get(cached)
    if module is None:
        module = next(
            (m for _n, m in _place_modules(ida_kernwin)
             if callable(getattr(m, cached, None))),
            None)
    return [(cached, module)] if module is not None else []


def _line_places(line, ida_kernwin, attempts):
    """
    Every way of naming a line that this build can actually construct.

    Returns ``(class name, instance)`` pairs. When a class has been proven
    to work before, only that one is built, so the discovery above happens
    once per session instead of once per trace event -- and if that
    remembered class no longer builds, discovery runs again rather than
    reporting "nothing to try".
    """
    cached = _accepted_place_class[0]

    def build(candidates):
        places = []
        for name, module in candidates:
            _place_name_modules[name] = module
            cls = getattr(module, name, None)
            if not callable(cls):
                _note(attempts, "%s is not callable" % name)
                continue
            if not isinstance(cls, type):
                #
                # place_t_as_* is a downcast helper, not a class: it is
                # callable and ends with place_t, so it scans exactly like a
                # place class -- but it builds nothing. A downcast helper
                # returns None for an argument it cannot convert rather than
                # raising, so without this a None is offered to jumpto as if
                # it were a place.
                #
                _note(attempts, "%s is a downcast helper, not a class" % name)
                continue

            # the constructor takes the line number on some builds and
            # nothing on others; either is acceptable, the viewer decides
            failure = "%s cannot be constructed" % name
            for args in ((int(line),), (0,)):
                try:
                    made = cls(*args)
                except Exception as exc:
                    failure = "%s(%s): %s: %s" % (name, args[0],
                                                  type(exc).__name__, exc)
                    continue
                if made is None:
                    failure = "%s(%s) returned None" % (name, args[0])
                    continue
                places.append((name, made))
                break
            else:
                _note(attempts, failure)
        return places

    if cached:
        places = build(_cached_candidates(cached, ida_kernwin))
        if places:
            return places
        # the remembered class turned out not to resolve or not to build
        # any more: drop whatever that probe complained about and start over
        del attempts[:]

    candidates = _discover_candidates(ida_kernwin)
    places = build(candidates)
    if not candidates:
        _note(attempts, "no *place_t names found in ida_kernwin or "
                        "ida_hexrays")
    return places


def _report_navigation_surface(vdui, ida_kernwin, attempts):
    """
    Dump the APIs that could move this cursor -- once, after a failed jump.

    Guessing IDA's navigation API from the outside has now been wrong three
    times over: ``simpleline_place_t`` turned out to be abstract, ``jumpto``
    has no widget-plus-address overload, and ``vdui_t`` has no
    ``switchto_myview``. Rather than a fourth guess, this prints what the
    build actually exposes, so the answer arrives inside the log the user is
    already sending instead of needing a separate probe run.

    It runs inside a UI callback, so it is never allowed to raise: a
    diagnostic that throws would break the navigation it exists to explain.
    """
    if _surface_reported[0]:
        return
    _surface_reported[0] = True

    try:
        parts = _navigation_surface_parts(vdui, ida_kernwin, attempts)
    except Exception as exc:
        pdbg("pseudocode nav surface could not be collected: %s: %s",
             type(exc).__name__, exc)
        return

    for part in parts:
        pdbg("pseudocode nav surface: %s", part)


def _navigation_surface_parts(vdui, ida_kernwin, attempts):
    """Build the diagnostic lines (separated so the dump cannot raise)."""
    try:
        import ida_hexrays
    except Exception:
        ida_hexrays = None

    parts = ["tried: %s" % ("; ".join(attempts) or "(nothing to try)")]
    parts.append("ida_kernwin *place_t names: %s" % sorted(
        n for n in dir(ida_kernwin) if n.endswith("place_t")))
    for name in ("jumpto", "activate_widget", "get_custom_viewer_place",
                 "custom_viewer_place_t", "simpleline_place_t"):
        parts.append("ida_kernwin.%s: %s" % (
            name, "present" if getattr(ida_kernwin, name, None) else
            "absent"))
    if ida_hexrays is not None:
        parts.append("ida_hexrays *place_t names: %s" % sorted(
            n for n in dir(ida_hexrays) if n.endswith("place_t")))
        parts.append("ida_hexrays place/jump/nav/cursor names: %s" % sorted(
            n for n in dir(ida_hexrays)
            if any(k in n.lower()
                   for k in ("place", "jump", "nav", "cursor"))))
        parts.append("ida_hexrays.vdui_t: %s" % sorted(
            n for n in dir(ida_hexrays.vdui_t) if not n.startswith("__")))
    parts.append("vdui: %s" % sorted(
        n for n in dir(vdui) if not n.startswith("__")))
    return parts


def _clone_targets(line, ida_kernwin, handles, attempts):
    """
    ``[label, place, view name, view]`` built from each view's own place.

    Every ``*place_t`` class on IDA 9.4 is abstract, so a place cannot be
    *constructed* -- but it can be cloned, and the clone is mutable. This is
    the shape IDA's own examples and the idavim plugin use::

        place, x, y = get_custom_viewer_place(view, False)
        target = place_t_as_simpleline_place_t(place.clone())
        target.n = line
        jumpto(view, target, x, y)

    A place belongs to the view it was read from, so each is bound to that
    view: handing view A's place to view B is a mismatch, not a fallback.
    """
    getter = getattr(ida_kernwin, "get_custom_viewer_place", None)
    if not callable(getter):
        _note(attempts, "ida_kernwin.get_custom_viewer_place is absent")
        return []

    downcast = getattr(ida_kernwin, "place_t_as_simpleline_place_t", None)
    targets = []
    for handle_name, handle in handles:
        try:
            got = getter(handle, False)
        except Exception as exc:
            _note(attempts, "get_custom_viewer_place(%s): %s: %s"
                  % (handle_name, type(exc).__name__, exc))
            continue
        if not got:
            _note(attempts, "get_custom_viewer_place(%s) returned nothing"
                  % handle_name)
            continue

        # IDAPython documents a bare place_t while working implementations
        # unpack a (place, x, y) triple; accept either rather than guess
        place = got[0] if isinstance(got, (tuple, list)) and got else got

        try:
            clone = place.clone()
        except Exception as exc:
            _note(attempts, "place.clone() on %s: %s: %s"
                  % (handle_name, type(exc).__name__, exc))
            continue

        if not callable(downcast):
            _note(attempts, "ida_kernwin.place_t_as_simpleline_place_t is absent")
            continue
        try:
            target = downcast(clone)
        except Exception as exc:
            _note(attempts, "place_t_as_simpleline_place_t: %s: %s"
                  % (type(exc).__name__, exc))
            continue
        if target is None:
            _note(attempts, "%s's place is not a simpleline_place_t" % handle_name)
            continue

        try:
            # a place naming a line before the first line is refused (or
            # worse, clamped somewhere surprising) -- never hand one over
            target.n = max(0, int(line))
        except Exception as exc:
            _note(attempts, "setting the line on %s's place: %s: %s"
                  % (handle_name, type(exc).__name__, exc))
            continue

        targets.append(("line_place(clone)", target, handle_name, handle))
    return targets


def _try_jump(ida_kernwin, targets, x, attempts, cache=None):
    """
    One pass over every ``(place, view)`` pairing worth trying.

    Returns the name of the pairing that landed, or None. A refusal
    (False) and an exception are recorded differently, because they are
    different diagnoses: the first means the place class is not the one this
    view takes, the second means the API itself differs on this build.

    ``cache``, when given, records the name of the place that worked so the
    caller never has to rediscover it.
    """
    # a column past the end of a rendered line is refused by some builds, so
    # the requested column is tried and then column zero -- the right line at
    # a coarse column beats the view not moving at all
    try:
        columns = [int(x)] if not x else [int(x), 0]
    except Exception:
        columns = [0]

    for place_name, place, handle_name, handle in targets:
        for column in columns:
            try:
                if ida_kernwin.jumpto(handle, place, column, 0):
                    if cache is not None:
                        cache[0] = place_name
                    return "jumpto(%s, %s, x=%d)" % (
                        handle_name, place_name, column)
            except Exception as exc:
                _note(attempts, "jumpto(%s, %s): %s: %s"
                      % (handle_name, place_name,
                         type(exc).__name__, exc))
                break
            _note(attempts, "jumpto(%s, %s, x=%d) refused"
                  % (handle_name, place_name, column))
    return None


def _jump_with_place(ida_kernwin, line, handles, x, attempts):
    """
    Produce a place for ``line`` and land it, cheapest route first.

    Returns the description of the pairing that landed, or None. Two routes:

    * **clone** the view's own place -- one API call, and the only route
      that works where no place class can be built at all.
    * **construct** a place class the build allows -- kept because cloning
      needs the view to already have a place, which a cold view may not.
      Latched off after it fails once, because where every class is abstract
      it fails identically on every trace event and would otherwise print
      the same seven refusals forever.
    """
    targets = _clone_targets(line, ida_kernwin, handles, attempts)
    if targets:
        how = _try_jump(ida_kernwin, targets, x, attempts)
        if how is not None:
            return how

    if _constructible[0] is False:
        _note(attempts, "no *place_t class can be constructed on this build")
        return None

    places = _line_places(line, ida_kernwin, attempts)
    if not places:
        _constructible[0] = False
        _note(attempts, "no *place_t class can be constructed on this build")
        return None

    return _try_jump(
        ida_kernwin,
        [(name, place, handle_name, handle)
         for name, place in places
         for handle_name, handle in handles],
        x, attempts, cache=_accepted_place_class)


def jump_to_item(vdui, line, x=0, length=1, activate=True, ea=None):
    """
    Place the cursor of a pseudocode widget on ``line`` / ``x``.

    Returns True **only** when the widget really accepted the navigation.

    ``length`` selects the whole rendered span on builds that support it.
    ``ea`` is accepted because the caller has it and it belongs in the
    diagnostics, but it is not a fallback of its own: IDA 9.4 exposes no
    ``jumpto(TWidget*, ea_t)`` overload, only the place-based one.

    The failure path matters more than the success one. ``jumpto`` *returns*
    False rather than raising when the place class does not match the view,
    and the only place that said why was a debug-level line nobody enables --
    so a sync that resolved, mapped and picked the correct expression still
    presented as "nothing happened". Every combination is attempted and the
    outcome reported to the output window.
    """
    if vdui is None or line is None:
        return False

    import ida_kernwin

    where = " line %d (x=%d%s)" % (
        line, x, ", ea=0x%X" % ea if ea is not None else "")

    attempts = []
    handles = _view_handles(vdui, attempts)
    if not handles:
        pdbg("pseudocode jump to%s failed: %s", where, "; ".join(attempts))
        return False

    how = _jump_with_place(ida_kernwin, line, handles, x, attempts)

    if how is None and activate:
        #
        # nothing moved. Some builds refuse to move the cursor of a widget
        # that is not the current one, so focus it and try once more --
        # *after* the unfocused attempt, so a sync never steals focus when
        # it did not have to. IDA 9.4 has no vdui_t.switchto_myview, so the
        # generic activation is what actually runs there.
        #
        focused = False
        switch = getattr(vdui, "switchto_myview", None)
        if callable(switch):
            try:
                switch()
                focused = True
            except Exception as exc:
                _note(attempts, "switchto_myview: %s: %s"
                      % (type(exc).__name__, exc))

        if not focused:
            for name, handle in handles:
                try:
                    ida_kernwin.activate_widget(handle, True)
                    focused = True
                    break
                except Exception as exc:
                    _note(attempts, "activate_widget(%s): %s: %s"
                          % (name, type(exc).__name__, exc))

        if focused:
            how = _jump_with_place(ida_kernwin, line, handles, x, attempts)

    if how is None:
        pdbg("pseudocode jump to%s failed: %s", where,
             "; ".join(attempts) or "no strategy to attempt")
        _report_navigation_surface(vdui, ida_kernwin, attempts)
        return False

    if attempts:
        pdbg("pseudocode jump to%s via %s, after: %s", where, how,
             "; ".join(attempts))
    else:
        # the clean case must still be visible: a sync that silently stops
        # logging is indistinguishable from one that silently stopped working
        pdbg("pseudocode jump to%s via %s", where, how)
    return True


def refresh_pseudocode(vdui):
    """Ask a pseudocode widget to redraw (used after a trace replacement)."""
    if vdui is None:
        return False
    try:
        vdui.refresh_ctext(False)
        return True
    except Exception:
        return False
