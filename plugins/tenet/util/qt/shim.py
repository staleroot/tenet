
#
# this global is used to indicate whether Qt bindings for python are present
# and available for use by Tenet / FRINET.
#

QT_AVAILABLE = False

#------------------------------------------------------------------------------
# Qt Binding Compatibility (PySide6 / PyQt5 / PySide2)
#------------------------------------------------------------------------------
#
#    we use this file to shim/re-alias a few Qt API's to ensure compatibility
#    between the popular Qt frameworks. these shims serve to reduce the number
#    of compatibility checks in the plugin code that consumes them.
#
#    FRINET targets IDA 9.4. IDA 9.2 moved from Qt5/PyQt5 to Qt6/PySide6
#    (9.1 and earlier still use PyQt5), so every widget is written against
#    aliases instead of one binding directly -- see ``_restore_qt6_moves``
#    and ``run_exec`` below.
#
#    WARNING: two Qt bindings must never be mixed inside a single process.
#    Qt widgets are not transferable between bindings, and IDA's own UI is
#    built on whichever binding IDA itself imported. Because of that, the
#    binding IDA has already loaded always wins (see sys.modules below) --
#    otherwise a machine with both PyQt5 and PySide6 installed would crash
#    the moment we tried to dock a panel into IDA's main window.
#

USING_PYQT5 = False
USING_PYSIDE2 = False
USING_PYSIDE6 = False

#: the name of the resolved binding ('PyQt5' / 'PySide2' / 'PySide6' / None)
QT_BINDING = None

import sys as _sys

#: preferred import order for a *cold* start (nothing imported yet)
_PREFERENCE_ORDER = ("PySide6", "PyQt5", "PySide2")

#
# order used when a binding has already been imported by the host. This is
# deliberately NOT the preference order: which binding IDA's own widgets are
# made of depends on the build (9.2+ ships PySide6, 9.1 and earlier PyQt5),
# and mixing two bindings in one process crashes on the first docked widget.
# In practice only IDA's binding is ever loaded, so this order is only a
# tie-break for an already-dangerous environment.
#
_HOST_ORDER = ("PyQt5", "PySide6", "PySide2")

def _already_loaded_binding():
    """
    Return the Qt binding the host (IDA) has already imported, if any.

    IDA imports its binding before any plugin runs, so this is the only
    choice that is guaranteed to be safe to dock into IDA's own widgets.
    """
    for name in _HOST_ORDER:
        if name in _sys.modules:
            return name
    return None

def _restore_qt6_moves(QtGui, QtWidgets):
    """
    Re-expose the classes Qt6 moved out of ``QtWidgets``.

    Qt6 relocated ``QAction``, ``QActionGroup`` and ``QShortcut`` from
    ``QtWidgets`` to ``QtGui``. This plugin -- and Tenet's original code --
    addresses them as ``QtWidgets.QAction`` throughout, so under PySide6
    every context menu would otherwise die with an AttributeError. Putting
    the names back costs nothing and keeps a single call site valid across
    every binding.
    """
    for name in ("QAction", "QActionGroup", "QShortcut"):
        if not hasattr(QtWidgets, name) and hasattr(QtGui, name):
            setattr(QtWidgets, name, getattr(QtGui, name))


def _try_load(name):
    """
    Import ``name``'s Qt modules and alias them onto the shared symbols.

    Returns True on success. Any ImportError (or an incompatible Qt build)
    leaves the globals untouched so the next binding can be tried.
    """
    global QT_AVAILABLE, QT_BINDING
    global USING_PYQT5, USING_PYSIDE2, USING_PYSIDE6
    global QtGui, QtCore, QtWidgets

    try:
        if name == "PyQt5":
            import PyQt5.QtGui as QtGui
            import PyQt5.QtCore as QtCore
            import PyQt5.QtWidgets as QtWidgets

        elif name == "PySide6":
            import PySide6.QtGui as QtGui
            import PySide6.QtCore as QtCore
            import PySide6.QtWidgets as QtWidgets

        elif name == "PySide2":
            import PySide2.QtGui as QtGui
            import PySide2.QtCore as QtCore
            import PySide2.QtWidgets as QtWidgets

        else:
            return False

    # binding is not installed (or its Qt runtime is unusable)
    except ImportError:
        return False

    #
    # alias the PySide naming onto the PyQt naming so the rest of the plugin
    # never has to care which binding it is talking to
    #
    if name != "PyQt5":
        QtCore.pyqtSignal = QtCore.Signal
        QtCore.pyqtSlot = QtCore.Slot

    #
    # Qt6 moved several classes out of QtWidgets and into QtGui. The whole
    # plugin (including code that predates FRINET) addresses them as
    # QtWidgets.<name>, so alias them back rather than rewrite every call
    # site -- this is what keeps the existing views working under PySide6.
    #
    if name == "PySide6":
        _restore_qt6_moves(QtGui, QtWidgets)

    QT_AVAILABLE = True
    QT_BINDING = name
    USING_PYQT5 = name == "PyQt5"
    USING_PYSIDE2 = name == "PySide2"
    USING_PYSIDE6 = name == "PySide6"
    return True

#------------------------------------------------------------------------------
# Binding Resolution
#------------------------------------------------------------------------------

# 1. the binding the host already loaded always wins (never mix bindings)
# 2. otherwise fall back to the documented preference order
if not _try_load(_already_loaded_binding() or ""):
    for _binding in _PREFERENCE_ORDER:
        if _try_load(_binding):
            break

del _try_load
del _already_loaded_binding
del _PREFERENCE_ORDER
del _HOST_ORDER

#------------------------------------------------------------------------------
# Cross-Binding Helpers
#------------------------------------------------------------------------------

def qt_class(name):
    """
    Return a Qt class by name, searching ``QtWidgets``, ``QtGui`` and
    ``QtCore``.

    Qt6 moved classes between these modules (``QAction``, ``QActionGroup``
    and ``QShortcut`` left ``QtWidgets`` for ``QtGui``; ``QStandardItem``
    and ``QStandardItemModel`` have always lived in ``QtGui``), and the
    pre-existing plugin picked names up through three star imports where
    each module shadowed the last. Searching all three is faithful to that
    and means nobody has to remember which module a given class ended up
    in -- a guess that is silently wrong until the code path runs.

    Raises ``AttributeError`` naming every place that was looked, so a
    future Qt rename is diagnosable from the message alone.
    """
    for module in (QtWidgets, QtGui, QtCore):
        candidate = getattr(module, name, None)
        if candidate is not None:
            return candidate

    raise AttributeError(
        "Qt class %r is in none of QtWidgets/QtGui/QtCore (binding: %s)"
        % (name, QT_BINDING))


def run_exec(dialog, *args):
    """
    Show a modal dialog (or popup menu) under any binding.

    Qt6 renamed ``exec_()`` to ``exec()``. PySide6 still carries ``exec_()``
    as a deprecated alias, but PyQt6 dropped it entirely, so the spelling is
    tried modern-first and the legacy one used only as a fallback -- that
    keeps the context menus in the pre-existing views working no matter
    which binding IDA was built against.

    ``args`` is forwarded so popup menus can take their global position.
    """
    function = getattr(dialog, "exec", None) or getattr(dialog, "exec_", None)
    if function is None:
        raise AttributeError(type(dialog).__name__ + " has neither exec() nor exec_()")
    return function(*args)


def wrapinstance(address, klass):
    """
    Cast a raw C++ pointer to a Qt wrapper object of type ``klass``.

    This is ``sip.wrapinstance`` under PyQt5 and ``shiboken*.wrapinstance``
    under PySide. Provided here so callers (eg, IDA popup menu injection)
    do not have to import a binding-specific module.
    """
    if USING_PYQT5:
        from PyQt5 import sip
        return sip.wrapinstance(int(address), klass)

    if USING_PYSIDE6:
        import shiboken6
        return shiboken6.wrapinstance(int(address), klass)

    if USING_PYSIDE2:
        import shiboken2
        return shiboken2.wrapinstance(int(address), klass)

    raise RuntimeError("No Qt binding available to wrap instance")
