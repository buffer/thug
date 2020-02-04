#!/usr/bin/env python


def bool_property(name, attrtype = bool, readonly = False, default = False):
    def getter(self):
        return attrtype(self.tag[name]) if self.tag.has_attr(name) else default

    def setter(self, value):
        self.tag[name] = attrtype(value)

    return property(getter) if readonly else property(getter, setter)
