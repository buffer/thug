import logging

from .Activator import Activator

log = logging.getLogger("Thug")


class Delegate:
    def __init__(self, code):
        self.code = code

    def DynamicInvoke(self, args):
        # log.warning(self.code.decode())
        return Activator(self)
