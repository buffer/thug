#!/usr/bin/env python

import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

try:
    from cStringIO import StringIO
except:
    from StringIO import StringIO

import bs4 as BeautifulSoup
import logging

from ActiveX.ActiveX import _ActiveXObject
from Element import Element
from Style.ElementCSSInlineStyle import ElementCSSInlineStyle
from .attr_property import attr_property
from .text_property import text_property

log = logging.getLogger("Thug")


class HTMLElement(Element, ElementCSSInlineStyle):
    id              = attr_property("id")
    title           = attr_property("title")
    lang            = attr_property("lang")
    dir             = attr_property("dir")
    className       = attr_property("class")

    def getInnerHTML(self):
        if not self.hasChildNodes():
            return ""

        html = StringIO()

        for tag in self.tag.contents:
            html.write(str(tag))

        return html.getvalue()

    def setInnerHTML(self, html):
        soup = BeautifulSoup.BeautifulSoup(html, "html5lib")
        # FIXME
        #self.tag.contents = []
        
        for node in soup.body.children:
            self.tag.append(node)

        for node in self.tag.descendants:
            name = getattr(node, 'name', None)
            if not name:
                continue
        
            p = getattr(self, '_handle_%s' % (name, ), None)
            if p:
                p(node)
            
    innerHTML = property(getInnerHTML, setInnerHTML)

    def _handle_object(self, object):
        log.warning(object)
                            
        classid = object.get('classid', None)
        id      = object.get('id', None)

        if classid and id: 
            setattr(self.doc.window, id, _ActiveXObject(self.window, classid, 'id'))

    # WARNING: NOT DEFINED IN W3C SPECS!
    def focus(self):
        pass

    @property
    def sourceIndex(self):
        return None
