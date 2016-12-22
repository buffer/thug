#!/usr/bin/env python

import logging

from .HTMLElement import HTMLElement
from .attr_property import attr_property
from .compatibility import thug_long

log = logging.getLogger("Thug")


class HTMLObjectElement(HTMLElement):
    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)
        self._window = self.doc.window

    def __getattr__(self, name):
        for (key, value) in self.tag.attrs.iteritems():
            if key != 'id':
                continue

            _obj = getattr(self.doc.window, value)
            if _obj:
                return getattr(_obj, name)

        if name in self.__dict__:
            return self.__dict__[name]

        log.info("HTMLObjectElement attribute not found: %s", (name, ))

    # PLEASE REVIEW ME!
    def __setattr__(self, name, value):
        if name == 'classid':
            self.setAttribute(name, value)
            return

        self.__dict__[name] = value

        if 'funcattrs' not in self.__dict__:
            return

        if name in self.__dict__['funcattrs']:
            self.__dict__['funcattrs'][name](value)

    @property
    def form(self):
        pass

    code            = attr_property("code")
    align           = attr_property("align")
    archive         = attr_property("archive")
    border          = attr_property("border")
    classid         = attr_property("classid")
    codeBase        = attr_property("codebase")
    codeType        = attr_property("codetype")
    data            = attr_property("data")
    declare         = attr_property("declare", bool)
    height          = attr_property("height")
    hspace          = attr_property("hspace", thug_long)
    name            = attr_property("name")
    standBy         = attr_property("standby")
    tabIndex        = attr_property("tabindex", thug_long, default = 0)
    type            = attr_property("type")
    useMap          = attr_property("usemap")
    vspace          = attr_property("vspace", thug_long)
    width           = attr_property("width")

    # Introduced in DOM Level 2
    @property
    def contentDocument(self):
        return self.doc if self.doc else None

    def setAttribute(self, name, value):
        # ActiveX registration
        if name == 'classid':
            from thug.ActiveX.ActiveX import register_object

            try:
                register_object(self, value)
            except:  # pylint:disable=bare-except
                return

        self.tag[name] = value

    @property
    def object(self):
        return self

    def definition(self, value):
        pass
