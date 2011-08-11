#!/usr/bin/env python
from __future__ import with_statement

import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from Element import Element
from Style.ElementCSSInlineStyle import ElementCSSInlineStyle
from attr_property import attr_property
from text_property import text_property

class HTMLElement(Element, ElementCSSInlineStyle):
    id              = attr_property("id")
    title           = attr_property("title")
    lang            = attr_property("lang")
    dir             = attr_property("dir")
    className       = attr_property("class")
    innerHTML       = text_property()
