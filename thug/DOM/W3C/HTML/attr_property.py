#!/usr/bin/env python


def attr_property(name, attrtype=str, readonly=False, default=None):
    def getter(self):
        return attrtype(self.tag[name]) if self.tag.has_attr(name) else default

    def setter(self, value):
        if attrtype in (int,) and str(value).endswith("px"):
            value = int(str(value).split("px", maxsplit=1)[0])

        self.tag[name] = attrtype(value)

    return property(getter) if readonly else property(getter, setter)
