import logging

log = logging.getLogger("Thug")


class WshCollection(list):
    def __getattr__(self, name):
        if name.lower() == 'length':
            return len(self)

        raise AttributeError

    def Item(self, pos):
        return self[pos]
