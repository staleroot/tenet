from tenet.util.qt import *
from tenet.util.qt.util import copy_to_clipboard

#------------------------------------------------------------------------------
# event_info_view.py -- Event Info View
#------------------------------------------------------------------------------
#
#    A two column table describing the currently selected trace event.
#
#    Written against the Qt shim aliases (never a binding directly) so it
#    runs under PySide6, PyQt5 or PySide2 -- see tenet/util/qt/shim.py.
#
#    Everything here is render-only: the interesting decisions (what a
#    missing offset means, whether an address is mapped) are made in
#    tenet/event_info.py, which is unit tested without a GUI.
#

#: the fields shown, in display order: (model key, column header)
EVENT_FIELDS = (
    ("idx",                "Index"),
    ("tid",                "Thread"),
    ("pc",                 "PC (runtime)"),
    ("off",                "Offset"),
    ("static_ea",          "Address (IDB)"),
    ("mapped",             "Mapped"),
    ("sync",               "Pseudocode"),
    ("registers_changed",  "Registers changed"),
    ("memory_reads",       "Memory read"),
    ("memory_writes",      "Memory written"),
)

#: fields whose value is an address, and are therefore copyable / navigable
ADDRESS_FIELDS = ("pc", "static_ea")

#: rows that get a distinct (dimmer) foreground to separate addressing from
#: the rest of the event, purely as a readability aid
_ADDRESSING_ROWS = frozenset(("pc", "off", "static_ea", "mapped"))


class EventInfoView(QtWidgets.QWidget):
    """
    A Qt widget rendering one trace event's details.
    """

    def __init__(self, controller, model, parent=None):
        super(EventInfoView, self).__init__(parent)
        self.controller = controller
        self.model = model
        self._init_ui()

        self.model.event_changed(self.refresh)

    def _init_ui(self):

        self._table = QtWidgets.QTreeWidget(self)
        self._table.setColumnCount(2)
        self._table.setHeaderLabels(["Field", "Value"])
        self._table.setHeaderHidden(False)
        self._table.setRootIsDecorated(False)
        self._table.setAlternatingRowColors(True)
        self._table.setSelectionMode(
            QtWidgets.QAbstractItemView.SingleSelection)
        self._table.setEditTriggers(
            QtWidgets.QAbstractItemView.NoEditTriggers)

        # the value column wants to stretch; the label column stays narrow
        header = self._table.header()
        header.setStretchLastSection(True)
        header.setSectionResizeMode(
            0, QtWidgets.QHeaderView.ResizeToContents)

        self._items = {}

        for key, label in EVENT_FIELDS:
            item = QtWidgets.QTreeWidgetItem([label, ""])
            self._table.addTopLevelItem(item)
            self._items[key] = item

        # actions
        self._action_copy = QtWidgets.QAction("Copy value", self)
        self._action_copy.triggered.connect(self._copy_selection)
        self._action_navigate = QtWidgets.QAction(
            "Navigate in disassembler", self)
        self._action_navigate.triggered.connect(self._navigate_selection)

        self._table.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._ctx_menu_handler)

        # layout
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self._table)
        self.setLayout(layout)

        self.refresh()

    #-------------------------------------------------------------------------
    # Rendering
    #-------------------------------------------------------------------------

    def refresh(self):
        """
        Re-render the table from the model.
        """
        rendered = self.model.rendered

        for key, item in self._items.items():
            item.setText(1, rendered.get(key, ""))

        self._apply_row_styling()
        self._update_row_states()

    def _apply_row_styling(self):
        """
        Dim the addressing rows so the delta rows read as a separate block.
        """
        palette = getattr(self.controller.pctx, "palette", None)
        if palette is None:
            return

        dimmed = getattr(palette, "hex_text_faded_fg", None)
        normal = getattr(palette, "hex_text_fg", None)
        if dimmed is None or normal is None:
            return

        for key, item in self._items.items():
            color = dimmed if key in _ADDRESSING_ROWS else normal
            for column in (0, 1):
                item.setForeground(column, QtGui.QBrush(color))

    def _update_row_states(self):
        """
        Mark rows the user cannot act on (nothing to copy / navigate to).
        """
        rendered = self.model.rendered

        # an address row with no address is not copyable
        for key in ADDRESS_FIELDS:
            value = rendered.get(key, "")
            self._items[key].setDisabled(value in ("", "n/a"))

        # navigation only makes sense for a mapped IDB address
        self._action_navigate.setEnabled(self.model.static_ea is not None)

        # nothing to copy at all when the model is empty
        has_content = any(
            rendered.get(key, "") not in ("", "n/a", "none", "not mapped")
            for key, _ in EVENT_FIELDS
        )
        self._action_copy.setEnabled(has_content)

    #-------------------------------------------------------------------------
    # Context menu / actions
    #-------------------------------------------------------------------------

    def _ctx_menu_handler(self, position):
        """
        Handle a right click event (populate/show context menu).
        """
        menu = QtWidgets.QMenu()
        menu.addAction(self._action_copy)

        # only offer navigation when there is an address to navigate to
        if self.model.static_ea is not None:
            menu.addAction(self._action_navigate)

        run_exec(menu, self.mapToGlobal(position))

    def _selected_key(self):
        """
        Return the model key of the selected row (or None).
        """
        selected = self._table.selectedItems()
        if not selected:
            return None

        row = selected[0]
        for key, item in self._items.items():
            if item is row:
                return key
        return None

    def _copy_selection(self):
        """
        Copy the selected row's value (or the whole table) to the clipboard.
        """
        key = self._selected_key()

        # nothing selected: copy the entire event as 'field=value' lines
        if key is None:
            lines = [
                "%s=%s" % (label, self.model.rendered.get(model_key, ""))
                for model_key, label in EVENT_FIELDS
            ]
            copy_to_clipboard("\n".join(lines))
            return True

        return self.controller.copy_field(key)

    def _navigate_selection(self):
        """
        Navigate the disassembler to the selected (or the static) address.
        """
        key = self._selected_key()

        # the 'pc' row is a runtime address, it does not exist in the IDB
        if key == "pc":
            return False

        return self.controller.navigate_to_static()
