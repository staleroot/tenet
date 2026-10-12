import sys
import time
import logging

from .shim import *

#
# the clipboard enum lives in QtGui, but which binding it comes from depends
# on the one the shim resolved (see shim.py) -- never import a binding
# directly here, or the plugin breaks on any host using a different one.
#
QClipboard = QtGui.QClipboard

#------------------------------------------------------------------------------
# Qt Fonts
#------------------------------------------------------------------------------

def MonospaceFont():
    """
    Convenience alias for creating a monospace Qt font object.
    """
    font = QtGui.QFont("Courier New")
    font.setStyleHint(QtGui.QFont.TypeWriter)
    return font

#------------------------------------------------------------------------------
# Qt Util
#------------------------------------------------------------------------------

def copy_to_clipboard(data):
    """
    Copy the given data (a string) to the system clipboard.
    """
    cb = QtWidgets.QApplication.clipboard()
    cb.clear(mode=QClipboard.Clipboard)
    cb.setText(data, mode=QClipboard.Clipboard)

def flush_qt_events():
    """
    Flush the Qt event pipeline.
    """
    app = QtCore.QCoreApplication.instance()
    app.processEvents()

def focus_window():
    """
    Lame helper function to help with dev/debug.
    """
    mb = QtWidgets.QMessageBox(get_qmainwindow())
    mb.setText("Click to take focus...")
    mb.setStandardButtons(QtWidgets.QMessageBox.Ok)
    button = mb.button(QtWidgets.QMessageBox.Ok)
    run_exec(mb)

def get_dpi_scale():
    """
    Get a DPI-afflicted value useful for consistent UI scaling.
    """
    font = MonospaceFont()
    font.setPointSize(normalize_font(120))
    fm = QtGui.QFontMetricsF(font)

    # xHeight is expected to be 40.0 at normal DPI
    return fm.height() / 173.0

def normalize_font(font_size):
    """
    Normalize the given font size based on the system DPI.
    """
    if sys.platform == "darwin": # macos is lame
        return font_size + 2
    return font_size

def get_qmainwindow():
    """
    Get the QMainWindow instance for the current Qt runtime.
    """
    app = QtWidgets.QApplication.instance()
    return [x for x in app.allWidgets() if x.__class__ is QtWidgets.QMainWindow][0]

def compute_color_on_gradient(percent, color1, color2):
    """
    Compute the color specified by a percent between two colors.
    """
    r1, g1, b1, _ = color1.getRgb()
    r2, g2, b2, _ = color2.getRgb()

    # compute the new color across the gradient of color1 -> color 2
    r = r1 + percent * (r2 - r1)
    g = g1 + percent * (g2 - g1)
    b = b1 + percent * (b2 - b1)

    # return the new color
    return QtGui.QColor(r,g,b)

#------------------------------------------------------------------------------
# Qt Scheduling
#------------------------------------------------------------------------------

_logger = logging.getLogger("Tenet.Util.Qt")


class QTimerScheduler(object):
    """
    Coalesce a burst of callbacks onto one single-shot :class:`QTimer`.

    Navigating a trace fires an index change per step, and a timeline scrub
    fires dozens per second. Each of those would otherwise open the
    decompiler, which cannot keep up and does not need to: only the most
    recent position matters. Restarting one single-shot timer per change
    means the work runs once, roughly ``delay_ms`` after the *last* change,
    so scrubbing stays smooth however fast the trace moves.

    This is the scheduler the pseudocode sync controller asks for. It lives
    here rather than in ``tenet.sync`` on purpose: that package must stay
    importable, and unit-testable, without any Qt at all.

    Create it on IDA's UI thread -- the plugin does so during init, which is
    already on that thread -- because that is the thread it fires on.
    """

    def __init__(self):
        self._timer = QtCore.QTimer()
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self._fire)
        self._pending = None

    @property
    def active(self):
        """Return True while a callback is queued and waiting to run."""
        return self._pending is not None

    def schedule(self, callback, delay_ms):
        """
        Queue ``callback`` to run once, ``delay_ms`` from now.

        Anything previously queued is replaced rather than run. That is the
        coalescing: a scrub of fifty steps becomes one update, not fifty.
        """
        self._pending = callback
        self._timer.setInterval(int(delay_ms))
        self._timer.start()

    def cancel(self):
        """Drop whatever was queued, without running it."""
        self._pending = None
        self._timer.stop()

    def _fire(self):
        callback, self._pending = self._pending, None
        if callback is None:
            return
        try:
            callback()
        except Exception:
            #
            # an exception escaping a Qt slot surfaces somewhere far from the
            # code that caused it, and takes the timer with it -- so report
            # it where it happened rather than let it vanish into Qt
            #
            _logger.exception("scheduled callback %r failed", callback)