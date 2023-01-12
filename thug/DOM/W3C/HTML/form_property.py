#!/usr/bin/env python

import logging

log = logging.getLogger("Thug")


def form_property(default = None):
    def getter(self):
        if not self.tag.parent.name.lower() in ('form', ):
            return default

        _form = getattr(self, '_form', None)
        if _form is None:
            self._form = log.DOMImplementation.createHTMLElement(self.doc, self.tag.parent)

        return self._form

    return property(getter)
