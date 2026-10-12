"""
Keep the pseudocode view in sync with the trace timeline.

Responsibilities, in the order they matter for responsiveness:

* **Coalesce** bursts of index changes into one update per tick. Scrubbing
  the timeline fires dozens of changes a second; the decompiler cannot
  keep up, and does not need to: only the last position matters.
* **Reject stale results.** Anything computed for an older index (a
  decompilation, a cursor jump) is dropped instead of applied.
* **Cache** decompilations and ctree maps in bounded LRU caches, keyed by
  function entry.
* **Prefetch** (only when idle) the ctree maps of the functions the trace
  is about to visit, so a scrub across a call boundary does not stall.
* **Never force** anything on the user: no window is opened, no function
  is decompiled, unless the pseudocode is already on screen (or the user
  explicitly asked).

Every IDA / Qt dependency is injected, so the whole controller is unit
tested head-less (see ``tests/test_frinet_sync.py``).
"""

import logging

from .cache import (
    DecompileCache,
    Generation,
    plan_prefetch,
)
from .pseudomap import PRECISION_NONE

#
# this module is deliberately importable head-less (every IDA dependency is
# injected), so the diagnostics are optional: outside IDA there is nothing to
# report to, and pulling in the real logger would cost the property that makes
# this file testable at all.
#
try:
    from tenet.util.log import pdbg
except Exception:  # pragma: no cover - head-less test runs
    def pdbg(fmt, *args):
        return

logger = logging.getLogger("Tenet.Sync.Controller")

#: how long to wait (ms) after the last index change before updating
DEFAULT_COALESCE_MS = 40

#: how many trace indexes around the current one to consider prefetching
DEFAULT_PREFETCH_BUDGET = 24

#: never scan more than this many events when building the prefetch index
MAX_PREFETCH_SCAN = 200000


#: only the first starved schedule is reported. the warning is about a wiring
#: mistake, not about each update, and a timeline scrub would otherwise print
#: one line per step -- so report the class of problem once and move on.
_warned_starved_scheduler = False


class NullScheduler(object):
    """
    A scheduler that runs nothing by itself.

    Tests (and any head-less caller) drive it explicitly with
    :meth:`run_pending`, which is the entire point of having it. What it must
    never do is sit *silently* in the middle of a production code path: a
    callback queued here and never run is indistinguishable from the feature
    simply not existing. That is exactly how pseudocode sync shipped dead --
    the timeline moved, the disassembly moved, and the C never followed --
    so the first such schedule is now reported.
    """

    def __init__(self):
        self._pending = None
        #: total schedule() calls; a caller can use this to notice starvation
        self.scheduled = 0

    def schedule(self, callback, delay_ms):
        """Queue ``callback`` for a later :meth:`run_pending`."""
        global _warned_starved_scheduler
        self._pending = callback
        self.scheduled += 1

        if not _warned_starved_scheduler:
            _warned_starved_scheduler = True
            logger.warning(
                "NullScheduler queued a callback and nothing will run it "
                "unless run_pending() is called (%r). Fine in tests; in the "
                "plugin this is a silent no-op, so it wants the Qt scheduler.",
                callback)

    def cancel(self):
        self._pending = None

    def run_pending(self):
        """Run whatever was queued. Returns True when something ran."""
        callback, self._pending = self._pending, None
        if callback is None:
            return False
        callback()
        return True


class SyncEvent(object):
    """The outcome of one synchronisation attempt (for tests / logging)."""

    def __init__(self, idx, ea, precision=PRECISION_NONE, applied=False,
                 stale=False, reason=""):
        self.idx = idx
        self.ea = ea
        self.precision = precision
        self.applied = applied
        self.stale = stale
        self.reason = reason

    def __repr__(self):
        return (f"SyncEvent(idx={self.idx}, ea={self.ea and hex(self.ea)}, "
                f"precision={self.precision!r}, applied={self.applied}, "
                f"stale={self.stale}, reason={self.reason!r})")


class PseudocodeSyncController(object):
    """
    Glue between a trace reader and the Hex-Rays pseudocode view.

    Parameters
    ----------
    hexrays_api:
        Anything exposing the ``tenet.sync.hexrays_api`` surface
        (``is_available``, ``function_entry_ea``, ``decompile``,
        ``build_pseudo_map``, ``find_pseudocode_widget``, ...). Injected so
        tests can substitute a fake.
    scheduler:
        Something with ``schedule(callback, delay_ms)`` / ``cancel()``.
        **Required**, with no default: a controller that is given nothing to
        drive it will queue updates that never run, and that failure is
        completely silent -- the timeline moves, the disassembly moves, and
        the pseudocode simply never follows. It was exactly this, once. So
        every construction site has to say what will run its work: the
        plugin passes a Qt QTimer-backed implementation, tests pass a
        :class:`NullScheduler` (or a fake) and drive it themselves.
    auto_open:
        Whether to obtain a pseudocode view when none already shows the
        traced function (see :meth:`_acquire_view` for the policy). True by
        default: the whole point of the feature is that stepping the trace
        shows where the C code is, and declining to show it because nothing
        was open yet meant it simply never worked on a fresh session.
    on_navigate:
        Called with ``(vdui, lookup_result)`` when the pseudocode should
        move. Defaults to the real Hex-Rays jump.
    """

    #: how many times a view the user closed gets reopened before the sync
    #: takes the hint and leaves it closed
    MAX_REOPENS = 1

    #: how many times a single function may fail to open before giving up
    #: on it. Bounded rather than permanent: a first attempt can fail for
    #: reasons that have nothing to do with the function (decompiler still
    #: initialising, analysis mid-run), and a permanent latch turns one such
    #: miss into "this feature never works again for this trace".
    MAX_OPEN_ATTEMPTS = 3

    def __init__(self, hexrays_api, scheduler, on_navigate=None,
                 coalesce_ms=DEFAULT_COALESCE_MS,
                 prefetch_budget=DEFAULT_PREFETCH_BUDGET,
                 auto_open=True):
        self.hexrays = hexrays_api
        if scheduler is None:
            raise ValueError(
                "PseudocodeSyncController requires a scheduler: without one "
                "every update it queues is silently dropped. Pass a "
                "NullScheduler() to drive it manually, or the plugin's Qt "
                "scheduler to run it on the UI thread.")
        self.scheduler = scheduler
        self.on_navigate = on_navigate
        self.coalesce_ms = coalesce_ms
        self.prefetch_budget = prefetch_budget
        self.auto_open = auto_open

        #: bounded caches shared across every navigation
        self.cache = DecompileCache()

        #: bumped whenever the world changed under a pending update
        self.generation = Generation()

        self._reader = None
        self._pending_idx = None
        self._events = []
        self._max_events = 64

        #
        # pseudocode view acquisition (see _acquire_view). Kept separate
        # from the decompile cache because unlike that, it is about the
        # user's windows: it must survive a coalesced update but reset when
        # the trace it belongs to is replaced.
        #
        #: True once this controller has opened or retargeted a view. If it
        #: is gone afterwards the user closed it, and a window someone just
        #: dismissed must not pop back open on the next step.
        self._acquired_a_view = False
        #: how many times each function (None = outside any known function)
        #: has failed to produce a view, so a broken one is not retried on
        #: every step -- but a transient first failure is not permanent
        #: either (see MAX_OPEN_ATTEMPTS)
        self._open_attempts = {}
        #: how many times we have found our view missing (i.e. closed)
        self._closed_by_user = 0
        #: why the most recent attempt to get a view declined; surfaced as
        #: the SyncEvent reason so the log answers "why nothing happened"
        self._no_view_reason = "no-pseudocode-widget"

        #
        # the list of prefetchable indexes, built once per trace and bound
        # to the reader that produced it (not the generation token: that
        # changes on every index move, which is exactly when we want this
        # list to survive)
        #
        self._mapped_cache = None
        self._mapped_cache_reader = None
        self._mapped_truncated = False

    #------------------------------------------------------------------
    # Lifecycle
    #------------------------------------------------------------------

    def attach_reader(self, reader):
        """Start tracking a (new) trace reader."""
        self.detach_reader()
        self._reader = reader
        self.generation.bump()
        self._reset_mapped_cache()
        self.cache.clear()

        #
        # begin watching for opened/closed pseudocode views now, rather
        # than the first time one is wanted. Hooks only ever see windows
        # opened *after* they are installed, so deferring this makes a view
        # the user already has open -- or opens while focused elsewhere --
        # invisible to every sync that follows, which reports
        # no-pseudocode-widget for a window that is plainly on screen.
        #
        try:
            self.hexrays.ensure_widget_tracking()
        except Exception:
            logger.debug("could not start pseudocode view tracking",
                         exc_info=True)

        if reader is not None:
            reader.idx_changed(self._on_idx_changed)

    def detach_reader(self):
        """Stop tracking, and forget everything computed for the old trace."""
        self.generation.bump()
        self.cache.clear()
        self._reset_mapped_cache()
        self._cancel_pending()
        self._reset_view_state()
        self._reader = None
        self._events = []

    def _reset_view_state(self):
        """Forget view acquisition history (new trace, or a fresh session)."""
        self._acquired_a_view = False
        self._open_attempts.clear()
        self._closed_by_user = 0
        self._no_view_reason = "no-pseudocode-widget"

    def _reset_mapped_cache(self):
        self._mapped_cache = None
        self._mapped_cache_reader = None
        self._mapped_truncated = False

    @property
    def reader(self):
        return self._reader

    #------------------------------------------------------------------
    # Events
    #------------------------------------------------------------------

    def _on_idx_changed(self, idx):
        """
        The trace position moved: queue one coalesced update.

        This runs on the reader's callback (the UI thread in IDA); it does
        the absolute minimum of work so timeline scrubbing stays smooth.
        """
        if self._reader is None:
            pdbg("sync: idx=%s ignored, no reader attached", idx)
            return

        self._pending_idx = idx
        self.generation.bump()
        self._cancel_pending()

        #
        # the pair of lines this and _flush's own produce is the whole
        # point: if "queued" appears and "flush" does not, the timer never
        # fired; if neither appears, the position change never reached the
        # sync layer at all. Without both, "nothing happened" is
        # indistinguishable between those two causes.
        #
        pdbg("sync: queued flush for idx=%s", idx)
        self.scheduler.schedule(self._flush, self.coalesce_ms)

    def _cancel_pending(self):
        try:
            self.scheduler.cancel()
        except Exception:
            logger.debug("scheduler.cancel() failed", exc_info=True)

    def flush(self):
        """
        Run any pending update now.

        Called directly by tests; the plugin relies on the scheduler.
        """
        return self._flush()

    #------------------------------------------------------------------
    # The update itself
    #------------------------------------------------------------------

    def _flush(self):
        """
        Apply the most recent pending index change.

        Returns a :class:`SyncEvent` describing what happened (never raises
        into the UI thread).
        """
        reader = self._reader
        if reader is None:
            pdbg("sync: flush skipped, no reader attached")
            return SyncEvent(-1, None, reason="no-reader")

        idx = self._pending_idx
        if idx is None:
            pdbg("sync: flush ran with nothing pending")
            return SyncEvent(-1, None, reason="nothing-pending")

        self._pending_idx = None
        token = self.generation.current()
        pdbg("sync: flush idx=%d", idx)

        try:
            event = self._sync_idx(reader, idx, token)
        except Exception as exc:
            # a decompiler surprise must never take the timeline with it
            logger.debug("sync of idx %s failed: %s", idx, exc, exc_info=True)
            pdbg("sync idx=%d raised %s: %s", idx, type(exc).__name__, exc)
            return SyncEvent(idx, None, reason=f"error: {exc}")

        self._record(event)
        pdbg("sync %r", event)
        return event

    def _sync_idx(self, reader, idx, token):
        """Synchronise the pseudocode view to one trace index."""
        ea = self._resolve_ea(reader, idx)
        if ea is None:
            return SyncEvent(idx, None, reason="unmapped")

        #
        # a view already showing this function is used exactly as it is;
        # otherwise acquire one, which is where the decision about opening
        # or retargeting a window gets made (see _acquire_view)
        #
        vdui = self.hexrays.find_pseudocode_widget(ea)
        if vdui is None:
            vdui = self._acquire_view(ea)
            if vdui is None:
                return SyncEvent(idx, ea, reason=self._no_view_reason)

        cfunc = self._cfunc_for(vdui, ea, token)
        if self._stale(token):
            return SyncEvent(idx, ea, reason="stale-cfunc")

        pmap = self._map_for(cfunc, token)
        if self._stale(token):
            return SyncEvent(idx, ea, reason="stale-map")

        if pmap is None:
            # the function decompiled, but nothing in it maps to this
            # address: leave the view exactly as it was
            return SyncEvent(idx, ea, precision=PRECISION_NONE,
                             reason="no-ctree-item")

        result = pmap.lookup(ea)
        if not result.found:
            return SyncEvent(idx, ea, precision=PRECISION_NONE,
                             reason="no-ctree-item")

        if self._stale(token):
            return SyncEvent(idx, ea, reason="stale-result")

        applied = self._navigate(vdui, result, ea)
        if self._stale(token):
            return SyncEvent(idx, ea, result.precision, stale=True,
                             reason="stale-after-navigate")

        # opportunistically warm the cache for where the trace goes next
        self._prefetch(reader, idx, token)

        return SyncEvent(idx, ea, result.precision, applied=applied)

    #------------------------------------------------------------------
    # Getting a view to synchronise
    #------------------------------------------------------------------

    def _acquire_view(self, ea):
        """
        Get a pseudocode view showing the function containing ``ea``.

        Reached only when no tracked view already shows it, so each branch
        here answers a different "how should we get one", and each is a
        decision rather than an accident:

        * A view *is* open, just on another function -> retarget it.
          ``open_pseudocode`` with ``OPF_REUSE`` reloads the existing window
          with the new function, so one window follows the trace instead of
          the trace dropping a window per function it walks into.
        * Nothing is open, and this controller has never driven a view ->
          open one. This is what makes "step the trace and see the C" work
          on a fresh session. Without it every step declined with
          ``no-pseudocode-widget`` while address resolution was perfect,
          which reads exactly like the feature being switched off.
        * Nothing is open, but this controller drove one earlier -> the user
          closed it. It is opened **once** more (a step is an explicit
          request to see the C, so one accidental close must not switch the
          feature off), then left alone: a window that keeps reappearing is
          worse than no synchronisation at all.

        Returns the ``vdui`` to synchronise, or None to decline -- in which
        case :attr:`_no_view_reason` says why, so the log answers the
        question "why did nothing happen".
        """
        if not self.auto_open:
            self._no_view_reason = "no-pseudocode-widget"
            return None

        any_view = None
        try:
            any_view = self.hexrays.find_pseudocode_widget()
        except Exception:
            logger.debug("could not enumerate pseudocode views", exc_info=True)

        if any_view is not None:
            how = "retargeting the open pseudocode view"
        elif self._acquired_a_view:
            #
            # we drove a view and it is gone: the user closed it. Come back
            # once -- a step is an explicit request to see the C, and a
            # window dismissed by accident should not switch the feature
            # off -- but a second closure is a decision, and a window that
            # keeps reappearing is worse than no synchronisation at all.
            #
            self._closed_by_user += 1
            if self._closed_by_user > self.MAX_REOPENS:
                self._no_view_reason = "pseudocode-closed-by-user"
                pdbg("pseudocode: the view was closed by the user %d times, "
                     "so it stays closed. %s", self._closed_by_user,
                     self._describe_views(ea))
                return None
            how = "reopening the view that was closed"
        else:
            how = "no pseudocode view was open"

        entry = self._entry(ea)
        attempts = self._open_attempts.get(entry, 0)
        if attempts >= self.MAX_OPEN_ATTEMPTS:
            where = ("0x%X" % entry if entry is not None
                     else "0x%X (outside any function)" % ea)
            self._no_view_reason = "pseudocode-open-failed"
            pdbg("pseudocode: declined, %s has already failed to open %d "
                 "times. %s", where, attempts, self._describe_views(ea))
            return None

        view = None
        open_error = None
        try:
            view = self.hexrays.open_pseudocode_widget(ea)
        except Exception as exc:
            open_error = "%s: %s" % (type(exc).__name__, exc)
            logger.debug("open_pseudocode_widget(0x%X) failed: %s", ea, exc)
            view = None

        if view is None:
            self._open_attempts[entry] = attempts + 1
            self._no_view_reason = "pseudocode-open-failed"
            pdbg("pseudocode: could not open a view for this function "
                 "(%s; attempt %d of %d). %s",
                 open_error or self._decompiler_error(ea),
                 attempts + 1, self.MAX_OPEN_ATTEMPTS,
                 self._describe_views(ea))
            return None

        self._acquired_a_view = True
        self._no_view_reason = "no-pseudocode-widget"
        pdbg("pseudocode: %s -> %s", how, self._describe_views(ea))
        return view

    def _entry(self, ea):
        """The function entry containing ``ea``, or None when unknown."""
        try:
            return self.hexrays.function_entry_ea(ea)
        except Exception:
            return None

    def _decompiler_error(self, ea):
        """
        Why the decompiler would not give us a function, or a placeholder.

        A bare ``pseudocode-open-failed`` says *that* it failed; this says
        *why* -- the difference between "this function will not decompile"
        and "Hex-Rays is not loaded" is invisible otherwise, and those two
        need completely different responses.
        """
        try:
            return self.hexrays.decompiler_error_text(ea) or "no reason given"
        except Exception:
            return "reason unavailable"

    def _describe_views(self, ea):
        """
        ``target=0x59280(sub_x) open=[0x401000(sub_y)]`` -- diagnostics.

        Spelled out because ``no-pseudocode-widget`` alone cannot separate
        "nothing is open" from "the wrong function is open", and those need
        opposite responses from the person reading the log.
        """
        entry = self._entry(ea)
        name = None
        if entry is not None:
            try:
                name = self.hexrays.function_name(entry)
            except Exception:
                name = None

        if entry is None:
            target = "unknown"
        elif name:
            target = "0x%X(%s)" % (entry, name)
        else:
            target = "0x%X" % entry

        try:
            open_views = self.hexrays.describe_open_pseudocode()
        except Exception:
            open_views = "(unavailable)"

        return "target=%s open=[%s]" % (target, open_views)

    #------------------------------------------------------------------
    # Steps
    #------------------------------------------------------------------

    def _resolve_ea(self, reader, idx):
        """
        Return the database address of one trace event (or None).

        ``off`` is the primary key: an event inside the traced module always
        translates through the resolved module origin. Events without an
        offset (external code, or a legacy trace) fall back to the legacy
        ASLR rebase. Either way the result must be an address the database
        actually contains -- events that cannot be mapped are never guessed
        into the pseudocode.
        """
        try:
            off = reader.get_offset(idx)
            if off is not None:
                static_ea = reader.analysis.translate_offset(off)
                if static_ea is not None:
                    return static_ea if self._is_mapped(reader, static_ea) else None

            # no offset: fall back to the legacy ASLR translation
            ea = reader.analysis.rebase_pointer(reader.get_ip(idx))
            if ea is None:
                return None
            if self._is_mapped(reader, ea) is False:
                return None
            return ea
        except Exception:
            logger.debug("could not resolve ea for idx %s", idx, exc_info=True)
            return None

    def _is_mapped(self, reader, ea):
        """
        Tri-state mapped check: True / False, or None when we cannot tell.

        The disassembler context exposes ``is_mapped``; when it is absent
        (a head-less reader, a stripped API) we accept the address rather
        than refuse to navigate at all.
        """
        analysis = getattr(reader, "analysis", None)
        checker = getattr(analysis, "_is_mapped", None)
        if checker is None:
            dctx = getattr(analysis, "_dctx", None)
            checker = getattr(dctx, "is_mapped", None) if dctx is not None else None
        if checker is None:
            return None
        try:
            return bool(checker(ea))
        except Exception:
            return None

    def _cfunc_for(self, vdui, ea, token):
        """Return the decompiled function of a view, using the cache."""
        entry_ea = None
        try:
            entry_ea = self.hexrays.function_entry_ea(ea)
        except Exception:
            entry_ea = None

        if entry_ea is None:
            # cannot tell which function this is: fall back to whatever the
            # view is currently showing
            try:
                return vdui.cfunc
            except Exception:
                return None

        cached = self.cache.get_cfunc(entry_ea)
        if cached is not None:
            return cached

        #
        # a view already showing this function is the cheapest possible
        # source of a cfunc: the decompiler already did the work
        #
        try:
            if vdui.cfunc and vdui.cfunc.entry_ea == entry_ea:
                cfunc = vdui.cfunc
                self.cache.put_cfunc(entry_ea, cfunc)
                return cfunc
        except Exception:
            pass

        if self._stale(token):
            return None

        cfunc = self.hexrays.decompile(entry_ea)
        if cfunc is not None:
            self.cache.put_cfunc(entry_ea, cfunc)
        return cfunc

    def _map_for(self, cfunc, token):
        """Return (and cache) the ctree map of a decompiled function."""
        if cfunc is None:
            return None

        entry_ea = getattr(cfunc, "entry_ea", None)
        cached = self.cache.get_map(entry_ea) if entry_ea is not None else None
        if cached is not None:
            return cached

        pmap = self.hexrays.build_pseudo_map(cfunc)
        if self._stale(token):
            # the user moved on while we were building the map: do not
            # publish a map that already describes an older world
            return pmap

        if pmap is not None and entry_ea is not None:
            self.cache.put_map(entry_ea, pmap)
        return pmap

    def _navigate(self, vdui, result, ea):
        """
        Move the pseudocode cursor. Returns True **only** when it moved.

        A False here, from an otherwise perfect :class:`SyncEvent`, means the
        widget refused the jump. That reason used to be swallowed into a
        debug-level log nobody enables, which is exactly how a sync that
        resolves and maps flawlessly can present as "nothing happened" with
        nothing in the output to contradict it.
        """
        try:
            if self.on_navigate is not None:
                return bool(self.on_navigate(vdui, result))
            return bool(self.hexrays.jump_to_item(
                vdui, result.line,
                x=(result.item.x if result.item else 0),
                length=(result.item.length if result.item else 1),
                ea=ea,
            ))
        except Exception as exc:
            logger.debug("pseudocode navigation failed", exc_info=True)
            pdbg("pseudocode navigation raised %s: %s", type(exc).__name__, exc)
            return False

    #------------------------------------------------------------------
    # Prefetch
    #------------------------------------------------------------------

    def _prefetch(self, reader, idx, token):
        """
        Warm the ctree map cache for the functions the trace heads into.

        Strictly opportunistic: any staleness (the user moved, the trace was
        replaced) aborts the whole batch, and only functions whose
        decompilation is already cached get their maps built -- prefetching
        never triggers a fresh decompilation.
        """
        try:
            mapped = self._mapped_idxs(reader)
        except Exception:
            return

        targets = plan_prefetch(idx, mapped, budget=self.prefetch_budget)

        for target in targets:
            if self._stale(token):
                return

            ea = self._resolve_ea(reader, target)
            if ea is None:
                continue

            entry_ea = self.hexrays.function_entry_ea(ea)
            if entry_ea is None or self.cache.get_map(entry_ea) is not None:
                continue

            # only reuse decompilations we already have: no new decompile()
            cfunc = self.cache.get_cfunc(entry_ea)
            if cfunc is None:
                continue

            pmap = self.hexrays.build_pseudo_map(cfunc)
            if pmap is not None:
                self.cache.put_map(entry_ea, pmap)

    def _mapped_idxs(self, reader):
        """
        Return the trace indexes whose events map into the database.

        Built once per trace and cached against the reader identity: the
        scan is the expensive part of prefetching, and the answer does not
        change while the same trace stays loaded.
        """
        if self._mapped_cache is not None and self._mapped_cache_reader is reader:
            return self._mapped_cache

        trace = reader.trace
        length = min(trace.length, MAX_PREFETCH_SCAN)

        mapped = []
        for idx in range(length):
            try:
                off = reader.get_offset(idx)
            except Exception:
                continue
            if off is not None:
                mapped.append(idx)
                continue
            # legacy / external events: only worth prefetching if they
            # rebase into the database at all
            try:
                ip = reader.get_ip(idx)
                if reader.analysis.rebase_pointer(ip) != ip:
                    mapped.append(idx)
            except Exception:
                continue

        self._mapped_cache = mapped
        self._mapped_cache_reader = reader
        self._mapped_truncated = length < trace.length
        return mapped

    #------------------------------------------------------------------
    # Introspection
    #------------------------------------------------------------------

    def _stale(self, token):
        """True when a newer index change happened since ``token``."""
        return not self.generation.is_current(token)

    def _record(self, event):
        self._events.append(event)
        if len(self._events) > self._max_events:
            del self._events[:-self._max_events]

    @property
    def events(self):
        """The most recent sync events (bounded, for tests / debugging)."""
        return list(self._events)

    def invalidate(self, entry_ea=None):
        """Forget cached decompilations (all, or just one function)."""
        self.generation.bump()
        self.cache.invalidate(entry_ea)
        if entry_ea is None:
            self._reset_mapped_cache()

    #------------------------------------------------------------------
    # Introspection for the UI
    #------------------------------------------------------------------

    def describe_target(self, ea):
        """
        Describe how ``ea`` maps into the pseudocode, without touching it.

        Returns ``(precision, line, function_name)`` -- ``line`` is 0-based,
        ``function_name`` may be None. Returns None when nothing is cached
        for the function containing ``ea``.

        This is what the event info panel shows. It is deliberately
        *non-forcing*: it only reads maps already sitting in the cache, so
        merely displaying a trace position can never trigger a
        decompilation the user did not ask for.
        """
        if ea is None or self._reader is None:
            return None

        try:
            entry_ea = self.hexrays.function_entry_ea(ea)
        except Exception:
            entry_ea = None
        if entry_ea is None:
            return None

        pmap = self.cache.get_map(entry_ea)
        if pmap is None:
            return None

        result = pmap.lookup(ea)
        if not result.found:
            return (result.precision, None, self._function_name(entry_ea))

        line = result.line
        return (result.precision, line, self._function_name(entry_ea))

    def _function_name(self, entry_ea):
        """Best-effort name of the function at ``entry_ea`` (or None)."""
        try:
            name = self.hexrays.function_name(entry_ea)
        except Exception:
            return None
        return name or None

    @property
    def prefetch_truncated(self):
        """
        True when the prefetch index only covers the start of the trace.

        Reported so the UI can say so rather than silently doing less.
        """
        return self._mapped_truncated
