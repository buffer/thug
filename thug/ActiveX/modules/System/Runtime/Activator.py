import logging

log = logging.getLogger("Thug")


class Activator:
    def __init__(self, delegate):
        self.delegate = delegate

    def CreateInstance(self, Type):
        pass
