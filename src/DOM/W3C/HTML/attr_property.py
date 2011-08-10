#!/usr/bin/env python
from __future__ import with_statement

def attr_property(name, attrtype = str, readonly = False, default = None):
    def getter(self):
        return attrtype(self.tag[name]) if self.tag.has_key(name) else default
        
    def setter(self, value):
        self.tag[name] = attrtype(value)
        
    return property(getter) if readonly else property(getter, setter)
