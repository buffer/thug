from .Activator import Activator


class Delegate:
    def __init__(self, code):
        self.code = code

    def DynamicInvoke(self, args):
        return Activator(self)
