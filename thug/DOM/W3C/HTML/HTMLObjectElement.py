#!/usr/bin/env python

import logging

from .HTMLElement import HTMLElement
from .attr_property import attr_property
from .bool_property import bool_property
from .form_property import form_property

log = logging.getLogger("Thug")


class HTMLObjectElement(HTMLElement):
    code     = attr_property("code")
    align    = attr_property("align")
    archive  = attr_property("archive")
    border   = attr_property("border")
    classid  = attr_property("classid")
    codeBase = attr_property("codebase")
    codeType = attr_property("codetype")
    data     = attr_property("data")
    declare  = bool_property("declare")
    form     = form_property()
    height   = attr_property("height")
    hspace   = attr_property("hspace", int)
    name     = attr_property("name")
    standBy  = attr_property("standby")
    tabIndex = attr_property("tabindex", int, default = 0)
    type     = attr_property("type")
    useMap   = attr_property("usemap")
    vspace   = attr_property("vspace", int)
    width    = attr_property("width")

    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)
        self._window = self.doc.window

    def __getattr__(self, name):
        for (key, value) in self.tag.attrs.items():
            if key.lower() not in ('id', ):
                continue

            obj = getattr(self.doc.window, value, None)
            if obj:
                attr = getattr(obj, name, None)
                if attr:
                    return attr

        log.info("HTMLObjectElement attribute not found: %s", (name, ))
        raise AttributeError

    def __setattr__(self, name, value):
        if name == 'classid':
            self.setAttribute(name, value)
            return

        self.__dict__[name] = value

        if 'funcattrs' not in self.__dict__:
            return

        if name in self.__dict__['funcattrs']:
            self.__dict__['funcattrs'][name](value)

    # Introduced in DOM Level 2
    @property
    def contentDocument(self):
        return self.doc if self.doc else None

    def setAttribute(self, name, value):
        if log.ThugOpts.features_logging:
            log.ThugLogging.Features.increase_setattribute_count()

        # ActiveX registration
        if name == 'classid':
            from thug.ActiveX.ActiveX import register_object

            try:
                register_object(self, value)
            except TypeError:
                return

        self.tag[name] = value

    @property
    def object(self):
        return self

    def definition(self, value):
        pass
