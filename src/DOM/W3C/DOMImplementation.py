#!/usr/bin/env python

import sys
import re
import string

import logging

try:
    from .HTML import *
except ValueError:
    from HTML import *

import bs4 as BeautifulSoup
from Node import Node

log = logging.getLogger("Thug")


class DOMImplementation(HTMLDocument.HTMLDocument):
    features = ( ('core'        , '1.0'),
                 ('core'        , '2.0'),
                 ('core'        , None ),
                 ('html'        , '1.0'),
                 ('html'        , '2.0'),
                 ('html'        , None ),
                 ('events'      , '2.0'),
                 ('events'      , None ),
                 ('uievents'    , '2.0'),
                 ('uievents'    , None ),
                 ('mouseevents' , '2.0'),
                 ('mouseevents' , None ),
                 ('htmlevents'  , '2.0'),
                 ('htmlevents'  , None ),
                 ('views'       , '2.0'),
                 ('views'       , None ),
                 ('stylesheets' , '2.0'),
                 ('stylesheets' , None ))
    
    @staticmethod
    def hasFeature(feature, version):
        if version == "":
            version = None
        return (feature.lower(), version) in DOMImplementation.features
        
    TAGS = {
        "html"          : HTMLHtmlElement.HTMLHtmlElement,
        "head"          : HTMLHeadElement.HTMLHeadElement,
        "link"          : HTMLLinkElement.HTMLLinkElement,
        "title"         : HTMLTitleElement.HTMLTitleElement,
        "meta"          : HTMLMetaElement.HTMLMetaElement,
        "base"          : HTMLBaseElement.HTMLBaseElement,
        "isindex"       : HTMLIsIndexElement.HTMLIsIndexElement,
        "style"         : HTMLStyleElement.HTMLStyleElement,
        "body"          : HTMLBodyElement.HTMLBodyElement,
        "form"          : HTMLFormElement.HTMLFormElement,
        "select"        : HTMLSelectElement.HTMLSelectElement,
        "optgroup"      : HTMLOptGroupElement.HTMLOptGroupElement,
        "option"        : HTMLOptionElement.HTMLOptionElement,
        "input"         : HTMLInputElement.HTMLInputElement,
        "textarea"      : HTMLTextAreaElement.HTMLTextAreaElement,
        "button"        : HTMLButtonElement.HTMLButtonElement,
        "label"         : HTMLLabelElement.HTMLLabelElement,
        "fieldset"      : HTMLFieldSetElement.HTMLFieldSetElement,
        "legend"        : HTMLLegendElement.HTMLLegendElement,
        "ul"            : HTMLUListElement.HTMLUListElement,
        "ol"            : HTMLOListElement.HTMLOListElement,
        "dl"            : HTMLDListElement.HTMLDListElement,
        "dir"           : HTMLDirectoryElement.HTMLDirectoryElement,
        "menu"          : HTMLMenuElement.HTMLMenuElement,
        "li"            : HTMLLIElement.HTMLLIElement,
        "div"           : HTMLDivElement.HTMLDivElement,
        "p"             : HTMLParagraphElement.HTMLParagraphElement,
        "h1"            : HTMLHeadingElement.HTMLHeadingElement,
        "h2"            : HTMLHeadingElement.HTMLHeadingElement,
        "h3"            : HTMLHeadingElement.HTMLHeadingElement,
        "h4"            : HTMLHeadingElement.HTMLHeadingElement,
        "h5"            : HTMLHeadingElement.HTMLHeadingElement,
        "h6"            : HTMLHeadingElement.HTMLHeadingElement,
        "q"             : HTMLQuoteElement.HTMLQuoteElement,
        "blockquote"    : HTMLQuoteElement.HTMLQuoteElement,
        "pre"           : HTMLPreElement.HTMLPreElement,
        "br"            : HTMLBRElement.HTMLBRElement,
        "basefont"      : HTMLBaseFontElement.HTMLBaseFontElement,
        "font"          : HTMLFontElement.HTMLFontElement,
        "hr"            : HTMLHRElement.HTMLHRElement,
        "ins"           : HTMLModElement.HTMLModElement,
        "del"           : HTMLModElement.HTMLModElement,
        "a"             : HTMLAnchorElement.HTMLAnchorElement,
        "object"        : HTMLObjectElement.HTMLObjectElement,
        "param"         : HTMLParamElement.HTMLParamElement,
        "img"           : HTMLImageElement.HTMLImageElement,
        "applet"        : HTMLAppletElement.HTMLAppletElement,
        "script"        : HTMLScriptElement.HTMLScriptElement,
        "frameset"      : HTMLFrameSetElement.HTMLFrameSetElement,
        "frame"         : HTMLFrameElement.HTMLFrameElement,
        "iframe"        : HTMLIFrameElement.HTMLIFrameElement,
        "table"         : HTMLTableElement.HTMLTableElement,
        "caption"       : HTMLTableCaptionElement.HTMLTableCaptionElement,
        "col"           : HTMLTableColElement.HTMLTableColElement,
        "colgroup"      : HTMLTableColElement.HTMLTableColElement,
        "thead"         : HTMLTableSectionElement.HTMLTableSectionElement,
        "tbody"         : HTMLTableSectionElement.HTMLTableSectionElement,
        "tfoot"         : HTMLTableSectionElement.HTMLTableSectionElement,
        "tr"            : HTMLTableRowElement.HTMLTableRowElement,
        "th"            : HTMLTableCellElement.HTMLTableCellElement,
        "td"            : HTMLTableCellElement.HTMLTableCellElement,
    }
        
    @staticmethod
    def createHTMLElement(doc, tag):
        if isinstance(tag, BeautifulSoup.NavigableString):
            return Node.wrap(doc, tag)

        if log.ThugOpts.Personality.isIE():
            if tag.name.lower() in ('t:animatecolor', ):
                return TAnimateColor.TAnimateColor(doc, tag)

        if tag.name.lower() in DOMImplementation.TAGS:
            return DOMImplementation.TAGS[tag.name.lower()](doc, tag)
        else:
            return HTMLElement.HTMLElement(doc, tag)
