#!/usr/bin/env python
from __future__ import with_statement

from HTMLElement import HTMLElement
from text_property import text_property

class HTMLTitleElement(HTMLElement):
    text            = text_property()
