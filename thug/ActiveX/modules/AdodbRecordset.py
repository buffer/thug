import collections
import six

from thug.DOM.JSClass import JSClass


class Fields(JSClass):
    def __init__(self, items = None):
        self.items = collections.OrderedDict() if items is None else items

    @property
    def count(self):
        return len(self.items)

    def Item(self, key):
        if key in six.string_types:
            item = getattr(self.items, key, None)
            if item:
                return item

        try:
            index = int(key)
        except ValueError:
            raise

        try:
            item = self.items[index]
        except KeyError:
            raise

        return item
