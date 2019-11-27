#!/usr/bin/env python

from .HTMLElement import HTMLElement
from .bool_property import bool_property
from .form_property import form_property


class HTMLFieldSetElement(HTMLElement):
    disabled = bool_property("disabled")
    form     = form_property()

    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)
