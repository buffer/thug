#!/usr/bin/env python

import sys, re, string

import PyV8

from DOMException import DOMException
from HTML.HTMLElement import HTMLElement
from HTML.HTMLHtmlElement import HTMLHtmlElement
from HTML.HTMLHeadElement import HTMLHeadElement
from HTML.HTMLLinkElement import HTMLLinkElement
from HTML.HTMLTitleElement import HTMLTitleElement
from HTML.HTMLMetaElement import HTMLMetaElement
from HTML.HTMLBaseElement import HTMLBaseElement
from HTML.HTMLIsIndexElement import HTMLIsIndexElement
from HTML.HTMLStyleElement import HTMLStyleElement
from HTML.HTMLBodyElement import HTMLBodyElement
from HTML.HTMLFormElement import HTMLFormElement
from HTML.HTMLSelectElement import HTMLSelectElement
from HTML.HTMLOptGroupElement import HTMLOptGroupElement
from HTML.HTMLOptionElement import HTMLOptionElement
from HTML.HTMLInputElement import HTMLInputElement
from HTML.HTMLTextAreaElement import HTMLTextAreaElement
from HTML.HTMLButtonElement import HTMLButtonElement
from HTML.HTMLLabelElement import HTMLLabelElement
from HTML.HTMLFieldSetElement import HTMLFieldSetElement
from HTML.HTMLLegendElement import HTMLLegendElement
from HTML.HTMLUListElement import HTMLUListElement
from HTML.HTMLOListElement import HTMLOListElement
from HTML.HTMLDListElement import HTMLDListElement
from HTML.HTMLDirectoryElement import HTMLDirectoryElement
from HTML.HTMLMenuElement import HTMLMenuElement
from HTML.HTMLLIElement import HTMLLIElement
from HTML.HTMLDivElement import HTMLDivElement
from HTML.HTMLParagraphElement import HTMLParagraphElement
from HTML.HTMLHeadingElement import HTMLHeadingElement
from HTML.HTMLQuoteElement import HTMLQuoteElement
from HTML.HTMLPreElement import HTMLPreElement
from HTML.HTMLBRElement import HTMLBRElement
from HTML.HTMLBaseFontElement import HTMLBaseFontElement
from HTML.HTMLFontElement import HTMLFontElement
from HTML.HTMLHRElement import HTMLHRElement
from HTML.HTMLModElement import HTMLModElement
from HTML.HTMLAnchorElement import HTMLAnchorElement
from HTML.HTMLObjectElement import HTMLObjectElement
from HTML.HTMLParamElement import HTMLParamElement
from HTML.HTMLImageElement import HTMLImageElement
from HTML.HTMLAppletElement import HTMLAppletElement
from HTML.HTMLScriptElement import HTMLScriptElement
from HTML.HTMLFrameSetElement import HTMLFrameSetElement
from HTML.HTMLFrameElement import HTMLFrameElement
from HTML.HTMLIFrameElement import HTMLIFrameElement
from HTML.HTMLDocument import HTMLDocument

class DOMImplementation(HTMLDocument):
    features = ( ('core'        , '1.0'),
                 ('core'        , '2.0'),
                 ('core'        , None ),
                 ('html'        , '1.0'),
                 ('html'        , '2.0'),
                 ('html'        , None ),
                 ('events'      , '2.0'),
                 ('events'      , None ),
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
        "html"          : HTMLHtmlElement,
        "head"          : HTMLHeadElement,
        "link"          : HTMLLinkElement,
        "title"         : HTMLTitleElement,
        "meta"          : HTMLMetaElement,
        "base"          : HTMLBaseElement,
        "isindex"       : HTMLIsIndexElement,
        "style"         : HTMLStyleElement,
        "body"          : HTMLBodyElement,
        "form"          : HTMLFormElement,
        "select"        : HTMLSelectElement,
        "optgroup"      : HTMLOptGroupElement,
        "option"        : HTMLOptionElement,
        "input"         : HTMLInputElement,
        "textarea"      : HTMLTextAreaElement,
        "button"        : HTMLButtonElement,
        "label"         : HTMLLabelElement,
        "fieldset"      : HTMLFieldSetElement,
        "legend"        : HTMLLegendElement,
        "ul"            : HTMLUListElement,
        "ol"            : HTMLOListElement,
        "dl"            : HTMLDListElement,
        "dir"           : HTMLDirectoryElement,
        "menu"          : HTMLMenuElement,
        "li"            : HTMLLIElement,
        "div"           : HTMLDivElement,
        "p"             : HTMLParagraphElement,
        "h1"            : HTMLHeadingElement,
        "h2"            : HTMLHeadingElement,
        "h3"            : HTMLHeadingElement,
        "h4"            : HTMLHeadingElement,
        "h5"            : HTMLHeadingElement,
        "h6"            : HTMLHeadingElement,
        "q"             : HTMLQuoteElement,
        "blockquote"    : HTMLQuoteElement,
        "pre"           : HTMLPreElement,
        "br"            : HTMLBRElement,
        "basefont"      : HTMLBaseFontElement,
        "font"          : HTMLFontElement,
        "hr"            : HTMLHRElement,
        "ins"           : HTMLModElement,
        "del"           : HTMLModElement,
        "a"             : HTMLAnchorElement,
        "object"        : HTMLObjectElement,
        "param"         : HTMLParamElement,
        "img"           : HTMLImageElement,
        "applet"        : HTMLAppletElement,
        "script"        : HTMLScriptElement,
        "frameset"      : HTMLFrameSetElement,
        "frame"         : HTMLFrameElement,
        "iframe"        : HTMLIFrameElement,
    }
        
    @staticmethod
    def createHTMLElement(doc, tag):        
        if DOMImplementation.TAGS.has_key(tag.name.lower()):            
            return DOMImplementation.TAGS[tag.name.lower()](doc, tag)
        else:
            return HTMLElement(doc, tag)

