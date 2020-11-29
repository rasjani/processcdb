# -*- coding: utf-8 -*-

import logging


LOG_LEVELS = {
    "notset": logging.NOTSET,
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
    "critical": logging.CRITICAL,
}
_APPNAME = "processcdb"
logging.basicConfig(format="[%(levelname)s]: %(message)s", level=logging.INFO)
LOGGER = logging.getLogger(_APPNAME)


def log_decorator(wrapped):
    """Decorator helper that logs function calls"""

    def log_enter_exit(*args, **kwargs):
        arguments = ""
        LOGGER.debug("{}({}) [ENTERING]".format(wrapped.__name__, arguments))
        result = wrapped(*args, **kwargs)
        LOGGER.debug("{}() [LEAVING]".format(wrapped.__name__))
        return result  # noqa: R504

    return log_enter_exit
