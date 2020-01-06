#!/usr/bin/env python


def bool_property(name, attrtype = bool, readonly = True, default = False, novalue = True):
    def getter(self):
        if novalue:
            return self.tag.has_attr(name)

        return attrtype(self.tag[name]) if self.tag.has_attr(name) else default

    def setter(self, value):
        self.tag[name] = attrtype(value)

    return property(getter) if readonly else property(getter, setter)
