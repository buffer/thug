#!/usr/bin/env python


def form_property(default = None):
    def getter(self):
        from thug.DOM.W3C.Core.DOMImplementation import DOMImplementation

        if not self.tag.parent.name.lower() in ('form', ):
            return default

        _form = getattr(self, '_form', None)
        if _form is None:
            self._form = DOMImplementation.createHTMLElement(self.doc, self.tag.parent)

        return self._form

    return property(getter)
