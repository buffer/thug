#!/usr/bin/env python

import logging

from .HTMLElement import HTMLElement
from .HTMLFormControlsCollection import HTMLFormControlsCollection
from .attr_property import attr_property

log = logging.getLogger("Thug")


class HTMLFormElement(HTMLElement):
    name          = attr_property("name")
    acceptCharset = attr_property("accept-charset", default = "")
    action        = attr_property("action")
    enctype       = attr_property("enctype", default = "application/x-www-form-urlencoded")
    encoding      = attr_property("enctype", default = "application/x-www-form-urlencoded")
    method        = attr_property("method", default = "get")
    target        = attr_property("target", default = "")

    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)

    def __getattr__(self, key):
        for tag in self.tag.children:
            if tag.name not in ('input', ):
                continue

            if 'name' in tag.attrs and tag.attrs['name'] in (key, ):
                from thug.DOM.W3C.Core.DOMImplementation import DOMImplementation
                return DOMImplementation.createHTMLElement(self.doc, tag)

        raise AttributeError

    @property
    def elements(self):
        from thug.DOM.W3C.Core.DOMImplementation import DOMImplementation

        nodes = []
        for tag in self.tag.children:
            if getattr(tag, 'name', None) and tag.name not in ('br', ):
                nodes.append(DOMImplementation.createHTMLElement(self.doc, tag))

        return HTMLFormControlsCollection(self.doc, nodes)

    @property
    def length(self):
        return len(self.elements)

    def submit(self):
        handler = getattr(log.DFT, 'do_handle_form', None)
        if handler:
            handler(self.tag)

    def reset(self):
        log.warning('[HTMLFormElement] reset method not defined')
