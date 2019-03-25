#!/usr/bin/env python

from .HTMLElement import HTMLElement
from .attr_property import attr_property
from .form_property import form_property


class HTMLFieldSetElement(HTMLElement):
    disabled = attr_property("disabled", bool)
    form     = form_property()

    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)
