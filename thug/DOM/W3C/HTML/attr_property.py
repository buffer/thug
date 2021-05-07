#!/usr/bin/env python


def attr_property(name, attrtype = str, readonly = False, default = None):
    def getter(self):
        return attrtype(self.tag[name]) if self.tag.has_attr(name) else default

    def setter(self, value):
        if attrtype in (int, ) and value.endswith('px'):
            value = value.split('px')[0]

        self.tag[name] = attrtype(value)

    return property(getter) if readonly else property(getter, setter)
