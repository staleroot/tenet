import os
import sys
import logging

from .misc import makedirs, is_plugin_dev
from ..integration.api import disassembler

#------------------------------------------------------------------------------
# Log / Print helpers
#------------------------------------------------------------------------------

def pmsg(message):
    """
    Print a 'plugin message' to the disassembler output window.
    """

    # prefix the message
    prefix_message = "[Tenet] %s" % message

    # only print to disassembler if its output window is alive
    if disassembler.is_msg_inited():
        disassembler.message(prefix_message)
    else:
        logger.info(message)

#
# Diagnostics.
#
# TENET_DEBUG turns on step-by-step messages in the disassembler's output
# window. This is deliberately separate from TENET_DEV, whose file log is a
# *recording* of what the plugin did -- it cannot show what the UI decided,
# which is where every reported failure has actually happened. The two
# therefore answer different questions:
#
#   TENET_DEV   "what did the plugin do?"      -> file, for us to read later
#   TENET_DEBUG "what is the plugin deciding?" -> output window, right now
#
# Arguments are lazily formatted so a disabled debug call costs a single
# attribute lookup and a return, which keeps it safe to leave in hot paths
# (the disassembly repaint hook runs on every screen update).
#
DEBUG_ENABLED = bool(os.getenv("TENET_DEBUG"))

def pdbg(fmt, *args):
    """
    Print a diagnostic message to the disassembler output window.

    No-op unless the ``TENET_DEBUG`` environment variable is set. Messages
    are prefixed so the whole session can be grepped out of an output log.
    """
    if not DEBUG_ENABLED:
        return
    try:
        message = fmt % args if args else fmt
    except Exception:
        message = "%s | %r" % (fmt, args)
    pmsg("  debug: %s" % message)

def get_log_dir():
    """
    Return the plugin log directory.
    """
    log_directory = os.path.join(
        disassembler.get_disassembler_user_directory(),
        "tenet_logs"
    )
    return log_directory

def logging_started():
    """
    Check if logging has been started.
    """
    return 'logger' in globals()

#------------------------------------------------------------------------------
# Logger Proxy
#------------------------------------------------------------------------------

class LoggerProxy(object):
    """
    Fake file-like stream object that redirects writes to a logger instance.
    """
    def __init__(self, logger, stream, log_level=logging.INFO):
        self._logger    = logger
        self._log_level = log_level
        self._stream    = stream

    def write(self, buf):
        for line in buf.rstrip().splitlines():
            self._logger.log(self._log_level, line.rstrip())
        if self._stream:
            self._stream.write(buf)

    def flush(self):
        pass

    def isatty(self):
        pass

#------------------------------------------------------------------------------
# Initialize Logging
#------------------------------------------------------------------------------

MAX_LOGS = 10
def cleanup_log_directory(log_directory):
    """
    Retain only the last 15 logs.
    """
    filetimes = {}

    # build a map of all the files in the directory, and their last modified time
    for log_name in os.listdir(log_directory):
        filepath = os.path.join(log_directory, log_name)
        if os.path.isfile(filepath):
            filetimes[os.path.getmtime(filepath)] = filepath

    # get the filetimes and check if there's enough to warrant cleanup
    times = list(filetimes.keys())
    if len(times) < MAX_LOGS:
        return

    logger.debug("Cleaning logs directory")

    # discard the newest 15 logs
    times.sort(reverse=True)
    times = times[MAX_LOGS:]

    # loop through the remaining older logs, and delete them
    for log_time in times:
        try:
            os.remove(filetimes[log_time])
        except Exception as e:
            logger.error("Failed to delete log %s" % filetimes[log_time])
            logger.error(e)

def start_logging():
    global logger

    # create the plugin logger
    logger = logging.getLogger("Tenet")

    #
    # only enable logging if the plugin-specific environment variable is
    # present. otherwive we return a stub logger to sinkhole messages.
    #

    if not is_plugin_dev():
        logger.disabled = True
        return logger

    # create a directory for plugin logs if it does not exist
    log_dir = get_log_dir()
    try:
        makedirs(log_dir)
    except Exception as e:
        logger.disabled = True
        return logger

    # construct the full log path
    log_path = os.path.join(log_dir, "tenet.%s.log" % os.getpid())

    # config the logger
    logging.basicConfig(
        filename=log_path,
        format='%(asctime)s | %(name)28s | %(levelname)7s: %(message)s',
        datefmt='%m-%d-%Y %H:%M:%S',
        level=logging.DEBUG
    )

    # proxy STDOUT/STDERR to the log files too
    stdout_logger = logging.getLogger('Tenet.STDOUT')
    stderr_logger = logging.getLogger('Tenet.STDERR')
    sys.stdout = LoggerProxy(stdout_logger, sys.stdout, logging.INFO)
    sys.stderr = LoggerProxy(stderr_logger, sys.stderr, logging.ERROR)

    # limit the number of logs we keep
    cleanup_log_directory(log_dir)

    return logger

#------------------------------------------------------------------------------
# Log Helpers
#------------------------------------------------------------------------------

def log_config_warning(self, logger, section, field):
    logger.warning("Config missing field '%s' in section '%s", field, section)
