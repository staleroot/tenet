from tenet.ui import *
from tenet.util.qt import QT_AVAILABLE

#
# the disassembler integration layer only imports cleanly inside IDA. The
# *model* in this file is deliberately pure, so it can be unit tested head
# less -- only the controller (which needs the dockable window / navigator)
# actually depends on the disassembler.
#
try:
    from tenet.util.misc import register_callback, notify_callback
    from tenet.integration.api import DockableWindow, disassembler
except ImportError:
    #
    # head-less fallback: the callback helpers are trivial, and the model
    # must keep working (eg, under the unit tests) without IDA
    #
    def register_callback(callbacks, callback):
        if callback not in callbacks:
            callbacks.append(callback)

    def notify_callback(callbacks):
        for callback in list(callbacks):
            callback()

    DockableWindow = None
    disassembler = None

#
# clipboard access is only meaningful with a UI; guarded so this module can
# still be imported head-less (eg, by the unit tests)
#
if QT_AVAILABLE:
    from tenet.util.qt.util import copy_to_clipboard
else:
    def copy_to_clipboard(data):
        raise RuntimeError("no Qt binding available for clipboard access")

#------------------------------------------------------------------------------
# event_info.py -- Event Info Controller
#------------------------------------------------------------------------------
#
#    The 'what just happened' panel: everything the trace knows about the
#    currently selected event, laid out so the addressing story is explicit.
#
#    The distinction this panel exists to make visible:
#
#        pc       -> the instruction pointer exactly as executed on the device
#        off      -> pc - slide, only defined for events inside the module
#        static_ea-> idb_module_start + off, where that event lives in the IDB
#
#    A legacy .tenet trace has no `off` at all, and an event that executed in
#    a library / the stack / unmapped memory has no offset by construction.
#    In both cases the panel says so in plain text rather than printing a
#    translated address that would be a guess.
#
#    The model below is deliberately free of Qt so its behaviour (what is
#    shown for an in-module event, an external event, a legacy trace, a
#    missing register) can be unit tested without a GUI.
#

class EventInfoController(object):
    """
    The Event Info Controller (Logic)
    """

    def __init__(self, pctx):
        self.pctx = pctx
        self.model = EventInfoModel(pctx)
        self.reader = None

        # UI components
        self.view = None
        self.dockable = None

        # the pseudocode sync controller (optional, wired by the context)
        self.sync = None

    def show(self, target=None, position=0):
        """
        Make the window attached to this controller visible.
        """

        # if there is no Qt (eg, our UI framework...) then there is no UI
        if not QT_AVAILABLE:
            return

        # the UI has already been created, and is also visible. nothing to do
        if (self.dockable and self.dockable.visible):
            return

        self.view = EventInfoView(self, self.model)
        new_dockable = DockableWindow("Event Info", self.view)

        # steal the dock position of a previously closed instance, if any
        if self.dockable:
            new_dockable.copy_dock_position(self.dockable)
        elif (target or position):
            new_dockable.set_dock_position(target, position)

        self.dockable = new_dockable
        self.dockable.show()

    def hide(self):
        """
        Hide the window attached to this controller.
        """

        # if there is no view/dockable, then there's nothing to try and hide
        if not(self.view and self.dockable):
            return

        # hide the dockable, and drop references to the widgets
        self.dockable.hide()
        self.view = None
        self.dockable = None

    def attach_reader(self, reader):
        """
        Attach a trace reader to this controller.
        """
        self.reader = reader
        self.model.reset()

        # attach trace reader signals to this controller / window
        reader.idx_changed(self._idx_changed)

        # render the state the reader is already in
        self._idx_changed(reader.idx)

    def detach_reader(self):
        """
        Detach the active trace reader from this controller.
        """
        self.reader = None
        self.model.reset()

    def set_sync(self, sync):
        """
        Attach the pseudocode sync controller (may be None).
        """
        self.sync = sync

    def copy_field(self, name):
        """
        Copy the rendered value of one field to the clipboard.
        """
        value = self.model.rendered.get(name)
        if value is None:
            return False
        copy_to_clipboard(value)
        return True

    def navigate_to_static(self):
        """
        Navigate the disassembler to the resolved static address.
        """
        if self.model.static_ea is None:
            return False
        disassembler[self.pctx].navigate(self.model.static_ea)
        return True

    #-------------------------------------------------------------------------
    # Callbacks
    #-------------------------------------------------------------------------

    def _idx_changed(self, idx):
        """
        The trace position has been changed.
        """
        self.model.update(self.reader, idx, sync=self.sync)

        if self.view:
            self.view.refresh()

class EventInfoModel(object):
    """
    The Event Info Model (Data)

    Holds both the raw values (ints, or None when unknown) and the rendered
    strings the view displays, so the view stays a dumb renderer and the
    interesting decisions are unit testable.
    """

    def __init__(self, pctx):
        self._pctx = pctx

        # callbacks (initialized before reset(), which notifies them)
        self._event_changed_callbacks = []

        self.reset()

    #----------------------------------------------------------------------
    # Properties
    #----------------------------------------------------------------------

    @property
    def arch(self):
        return self._pctx.arch

    #----------------------------------------------------------------------
    # Public
    #----------------------------------------------------------------------

    def reset(self):
        self.idx = -1
        self.length = 0

        # thread (segment) id of the event
        self.tid = None

        # the three addressing stages (see module docstring)
        self.pc = None
        self.off = None
        self.static_ea = None

        # tri-state mapping status: True / False / None (unknown)
        self.mapped = None

        # how the trace itself describes this event's addressing
        self.offset_source = "unknown"  # 'frinet' / 'legacy' / 'external'

        # what changed at this event
        self.registers_changed = {}
        self.memory_reads = []
        self.memory_writes = []

        # the sync controller's verdict on this address, if it has one
        self.sync_precision = None
        self.sync_line = None
        self.sync_function = None

        # { field_name: rendered_string } for display / clipboard
        self.rendered = {}

        self._notify_event_changed()

    def update(self, reader, idx, sync=None):
        """
        Rebuild the model for ``idx`` of ``reader``.
        """
        if not reader:
            self.reset()
            return

        trace = reader.trace

        self.idx = idx
        self.length = trace.length

        #--- addressing -----------------------------------------------------

        segment = None
        try:
            segment = trace.get_segment(idx)
        except Exception:
            segment = None

        self.tid = getattr(segment, "id", None)

        self.pc = reader.get_ip(idx)
        self.off = reader.get_offset(idx)

        #
        # resolve the static address through the offset path whenever the
        # event carries one; that is the only translation we trust, as the
        # legacy region heuristic can mislead on rebased / partial images
        #
        self.static_ea = None
        if self.off is not None:
            try:
                self.static_ea = reader.analysis.translate_offset(self.off)
            except Exception:
                self.static_ea = None

        #
        # 'mapped' is answered against the *database*, and is only meaningful
        # when we actually have a candidate address to test
        #
        self.mapped = None
        if self.static_ea is not None:
            try:
                self.mapped = bool(disassembler[self._pctx].is_mapped(self.static_ea))
            except Exception:
                self.mapped = None

        #
        # an absent offset has two very different causes, and the panel must
        # say which: a legacy .tenet trace never carried offsets at all,
        # whereas a .frinet event without one executed outside the module
        #
        if self.off is not None:
            self.offset_source = "frinet"
        elif getattr(reader, "has_offsets", False):
            self.offset_source = "external"
        else:
            self.offset_source = "legacy"

        #--- deltas ---------------------------------------------------------

        try:
            self.registers_changed = trace.get_reg_delta(idx) or {}
        except Exception:
            self.registers_changed = {}

        self.memory_reads = self._collect_memory(trace.get_read_delta, idx)
        self.memory_writes = self._collect_memory(trace.get_write_delta, idx)

        #--- sync verdict ---------------------------------------------------

        self.sync_precision = None
        self.sync_line = None
        self.sync_function = None

        if sync is not None and self.static_ea is not None:
            try:
                verdict = sync.describe_target(self.static_ea)
            except Exception:
                verdict = None

            if verdict:
                self.sync_precision, self.sync_line, self.sync_function = verdict

        #--- render ---------------------------------------------------------

        self._render()
        self._notify_event_changed()

    def _collect_memory(self, getter, idx, limit=16):
        """
        Collect one event's memory delta as a list of ``(address, data)``.

        Truncated to ``limit`` entries: the panel is a summary, and a
        memcpy-heavy event can touch thousands of bytes in one step.
        """
        try:
            delta = getter(idx)
        except Exception:
            return []

        if not delta:
            return []

        entries = []
        try:
            items = delta.items()
        except AttributeError:
            items = delta

        for address, data in items:
            entries.append((address, data))
            if len(entries) >= limit:
                break

        return entries

    def _render(self):
        """
        Build the { field: rendered string } table the view displays.
        """
        nibbles = self.arch.POINTER_SIZE * 2
        rendered = {}

        def hex_or(value, placeholder="n/a"):
            if value is None:
                return placeholder
            return "0x%0*X" % (nibbles, value)

        rendered["idx"] = "{:,} / {:,}".format(
            max(self.idx, 0), max(self.length, 0)) if self.idx >= 0 else "n/a"

        rendered["tid"] = str(self.tid) if self.tid is not None else "n/a"
        rendered["pc"] = hex_or(self.pc)

        #
        # an absent offset is not the same as a zero offset: say which of
        # the three situations we are actually in
        #
        if self.off is not None:
            rendered["off"] = "0x%X" % self.off
        elif self.offset_source == "legacy":
            rendered["off"] = "no offsets (legacy trace)"
        else:
            rendered["off"] = "external (outside module)"

        rendered["static_ea"] = hex_or(self.static_ea)

        if self.mapped is None:
            rendered["mapped"] = "unknown"
        else:
            rendered["mapped"] = "yes" if self.mapped else "no"

        rendered["registers_changed"] = ", ".join(
            sorted(self.registers_changed.keys())) or "none"

        rendered["memory_reads"] = self._render_memory(self.memory_reads, nibbles)
        rendered["memory_writes"] = self._render_memory(self.memory_writes, nibbles)

        # the sync verdict, in the precision vocabulary the user can read
        rendered["sync"] = self._render_sync()

        self.rendered = rendered

    @staticmethod
    def _render_memory(entries, nibbles):
        if not entries:
            return "none"
        return ", ".join("0x%0*X" % (nibbles, address) for address, _ in entries)

    def _render_sync(self):
        if self.sync_precision is None:
            return "not mapped"

        label = self.sync_precision
        if self.sync_line is not None:
            label += " (line %d)" % (self.sync_line + 1)
        if self.sync_function is not None:
            label += " in %s" % self.sync_function
        return label

    #----------------------------------------------------------------------
    # Callbacks
    #----------------------------------------------------------------------

    def event_changed(self, callback):
        """
        Subscribe a callback for an event changed event.
        """
        register_callback(self._event_changed_callbacks, callback)

    def _notify_event_changed(self):
        """
        Notify listeners of an event changed event.
        """
        notify_callback(self._event_changed_callbacks)
