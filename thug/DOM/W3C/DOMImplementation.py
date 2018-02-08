#!/usr/bin/env python

import logging

from lxml.html import builder as E
from lxml.html import tostring
import bs4 as BeautifulSoup

import thug.DOM.W3C.HTML as HTML

log = logging.getLogger("Thug")


class DOMImplementation(HTML.HTMLDocument):
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
        "html"          : HTML.HTMLHtmlElement,
        "head"          : HTML.HTMLHeadElement,
        "link"          : HTML.HTMLLinkElement,
        "title"         : HTML.HTMLTitleElement,
        "meta"          : HTML.HTMLMetaElement,
        "base"          : HTML.HTMLBaseElement,
        "isindex"       : HTML.HTMLIsIndexElement,
        "style"         : HTML.HTMLStyleElement,
        "body"          : HTML.HTMLBodyElement,
        "form"          : HTML.HTMLFormElement,
        "select"        : HTML.HTMLSelectElement,
        "optgroup"      : HTML.HTMLOptGroupElement,
        "option"        : HTML.HTMLOptionElement,
        "input"         : HTML.HTMLInputElement,
        "textarea"      : HTML.HTMLTextAreaElement,
        "button"        : HTML.HTMLButtonElement,
        "label"         : HTML.HTMLLabelElement,
        "fieldset"      : HTML.HTMLFieldSetElement,
        "legend"        : HTML.HTMLLegendElement,
        "ul"            : HTML.HTMLUListElement,
        "ol"            : HTML.HTMLOListElement,
        "dl"            : HTML.HTMLDListElement,
        "dir"           : HTML.HTMLDirectoryElement,
        "menu"          : HTML.HTMLMenuElement,
        "li"            : HTML.HTMLLIElement,
        "div"           : HTML.HTMLDivElement,
        "p"             : HTML.HTMLParagraphElement,
        "h1"            : HTML.HTMLHeadingElement,
        "h2"            : HTML.HTMLHeadingElement,
        "h3"            : HTML.HTMLHeadingElement,
        "h4"            : HTML.HTMLHeadingElement,
        "h5"            : HTML.HTMLHeadingElement,
        "h6"            : HTML.HTMLHeadingElement,
        "q"             : HTML.HTMLQuoteElement,
        "blockquote"    : HTML.HTMLQuoteElement,
        "span"          : HTML.HTMLSpanElement,
        "pre"           : HTML.HTMLPreElement,
        "br"            : HTML.HTMLBRElement,
        "basefont"      : HTML.HTMLBaseFontElement,
        "font"          : HTML.HTMLFontElement,
        "hr"            : HTML.HTMLHRElement,
        "ins"           : HTML.HTMLModElement,
        "del"           : HTML.HTMLModElement,
        "a"             : HTML.HTMLAnchorElement,
        "object"        : HTML.HTMLObjectElement,
        "param"         : HTML.HTMLParamElement,
        "img"           : HTML.HTMLImageElement,
        "applet"        : HTML.HTMLAppletElement,
        "script"        : HTML.HTMLScriptElement,
        "frameset"      : HTML.HTMLFrameSetElement,
        "frame"         : HTML.HTMLFrameElement,
        "iframe"        : HTML.HTMLIFrameElement,
        "table"         : HTML.HTMLTableElement,
        "caption"       : HTML.HTMLTableCaptionElement,
        "col"           : HTML.HTMLTableColElement,
        "colgroup"      : HTML.HTMLTableColElement,
        "thead"         : HTML.HTMLTableSectionElement,
        "tbody"         : HTML.HTMLTableSectionElement,
        "tfoot"         : HTML.HTMLTableSectionElement,
        "tr"            : HTML.HTMLTableRowElement,
        "th"            : HTML.HTMLTableCellElement,
        "td"            : HTML.HTMLTableCellElement,
        "media"         : HTML.HTMLMediaElement,
        "audio"         : HTML.HTMLAudioElement,
    }

    @staticmethod
    def createHTMLElement(doc, tag):
        from .Node import Node

        if isinstance(tag, BeautifulSoup.NavigableString):
            return Node.wrap(doc, tag)

        if log.ThugOpts.Personality.isIE():
            if tag.name.lower() in ('t:animatecolor', ):
                return HTML.TAnimateColor(doc, tag)

            if tag.name.lower() in ('audio', ) and log.ThugOpts.Personality.browserMajorVersion < 9:
                return HTML.HTMLElement(doc, tag)

        if tag.name.lower() in DOMImplementation.TAGS:
            return DOMImplementation.TAGS[tag.name.lower()](doc, tag)

        return HTML.HTMLElement(doc, tag)

    def _createHTMLDocument(self, title = None):
        body  = E.BODY()
        title = E.TITLE(title) if title else ""
        head  = E.HEAD(title)
        html  = E.HTML(head, body)

        soup = BeautifulSoup.BeautifulSoup(tostring(html, doctype = '<!doctype html>'), "lxml")
        return DOMImplementation(soup)
