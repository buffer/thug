#!/usr/bin/env python

from thug.DOM.W3C.HTML import HTMLAnchorElement
from thug.DOM.W3C.HTML import HTMLAppletElement
from thug.DOM.W3C.HTML import HTMLBRElement
from thug.DOM.W3C.HTML import HTMLBaseElement
from thug.DOM.W3C.HTML import HTMLBaseFontElement
from thug.DOM.W3C.HTML import HTMLBodyElement
from thug.DOM.W3C.HTML import HTMLButtonElement
#from thug.DOM.W3C.HTML import HTMLCollection
from thug.DOM.W3C.HTML import HTMLDListElement
from thug.DOM.W3C.HTML import HTMLDirectoryElement
from thug.DOM.W3C.HTML import HTMLDivElement
from thug.DOM.W3C.HTML import HTMLDocument
from thug.DOM.W3C.HTML import HTMLElement
from thug.DOM.W3C.HTML import HTMLFieldSetElement
from thug.DOM.W3C.HTML import HTMLFontElement
from thug.DOM.W3C.HTML import HTMLFormElement
from thug.DOM.W3C.HTML import HTMLFrameElement
from thug.DOM.W3C.HTML import HTMLFrameSetElement
from thug.DOM.W3C.HTML import HTMLHRElement
from thug.DOM.W3C.HTML import HTMLHeadElement
from thug.DOM.W3C.HTML import HTMLHeadingElement
from thug.DOM.W3C.HTML import HTMLHtmlElement
from thug.DOM.W3C.HTML import HTMLIFrameElement
from thug.DOM.W3C.HTML import HTMLImageElement
from thug.DOM.W3C.HTML import HTMLInputElement
from thug.DOM.W3C.HTML import HTMLIsIndexElement
from thug.DOM.W3C.HTML import HTMLLIElement
from thug.DOM.W3C.HTML import HTMLLabelElement
from thug.DOM.W3C.HTML import HTMLLegendElement
from thug.DOM.W3C.HTML import HTMLLinkElement
from thug.DOM.W3C.HTML import HTMLMenuElement
from thug.DOM.W3C.HTML import HTMLMetaElement
from thug.DOM.W3C.HTML import HTMLModElement
from thug.DOM.W3C.HTML import HTMLOListElement
from thug.DOM.W3C.HTML import HTMLObjectElement
from thug.DOM.W3C.HTML import HTMLOptGroupElement
from thug.DOM.W3C.HTML import HTMLOptionElement
#from thug.DOM.W3C.HTML import HTMLOptionsCollection
from thug.DOM.W3C.HTML import HTMLParagraphElement
from thug.DOM.W3C.HTML import HTMLParamElement
from thug.DOM.W3C.HTML import HTMLPreElement
from thug.DOM.W3C.HTML import HTMLQuoteElement
from thug.DOM.W3C.HTML import HTMLScriptElement
from thug.DOM.W3C.HTML import HTMLSelectElement
from thug.DOM.W3C.HTML import HTMLStyleElement
from thug.DOM.W3C.HTML import HTMLTableCaptionElement
from thug.DOM.W3C.HTML import HTMLTableCellElement
from thug.DOM.W3C.HTML import HTMLTableColElement
from thug.DOM.W3C.HTML import HTMLTableElement
from thug.DOM.W3C.HTML import HTMLTableRowElement
from thug.DOM.W3C.HTML import HTMLTableSectionElement
from thug.DOM.W3C.HTML import HTMLTextAreaElement
from thug.DOM.W3C.HTML import HTMLTitleElement
from thug.DOM.W3C.HTML import HTMLUListElement
from thug.DOM.W3C.HTML import TAnimateColor

import logging

import bs4 as BeautifulSoup
from .Node import Node

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
