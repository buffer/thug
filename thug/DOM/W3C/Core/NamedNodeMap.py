#!/usr/bin/env python

from .Attr import Attr
from thug.DOM.JSClass import JSClass


class NamedNodeMap(JSClass):
    def __init__(self, doc, tag):
        self.doc = doc
        self.tag = tag

    def __len__(self):
        return self.length

    def __getattr__(self, key):
        return self.getNamedItem(key)

    def __getitem__(self, key):
        return self.item(int(key))

    def getNamedItem(self, name):
        if name not in self.tag.attrs:
            return None

        attr = Attr(self.doc, None, name)
        attr.nodeValue = self.tag.attrs[name]
        return attr

    def setNamedItem(self, attr):
        oldvalue = self.tag.attrs.get(attr.name, None)
        self.tag.attrs[attr.name] = attr.value

        if oldvalue is None:
            return None

        oldattr = Attr(self.doc, None, attr.name)
        oldattr.value = oldvalue
        return oldattr

    def removeNamedItem(self, name):
        if name in self.tag.attrs:
            del self.tag.attrs[name]

    def item(self, index):
        names = [name for name in self.tag.attrs]

        if index < 0 or index >= len(names):
            return None

        return self.getNamedItem(names[index])

    @property
    def length(self):
        return len(self.tag.attrs)
