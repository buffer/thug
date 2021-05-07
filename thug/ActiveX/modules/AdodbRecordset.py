import collections

from thug.DOM.JSClass import JSClass


class Fields(JSClass):
    def __init__(self, items = None):
        self.items = collections.OrderedDict() if items is None else items

    @property
    def count(self):
        return len(self.items)

    def item(self, key):
        if isinstance(key, str):
            return getattr(self.items, key, None)

        try:
            index = int(key)
        except ValueError: # pragma: no cover
            return None

        if index < 0 or index > self.count - 1:
            return None

        return self.items[index] # pragma: no cover
