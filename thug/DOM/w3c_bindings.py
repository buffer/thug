#!/usr/bin/env python
#
# w3c_bindings.py
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston,
# MA  02111-1307  USA


from thug.DOM.W3C.Attr import Attr
from thug.DOM.W3C.CDATASection import CDATASection
from thug.DOM.W3C.CharacterData import CharacterData
from thug.DOM.W3C.Comment import Comment
from thug.DOM.W3C.DOMException import DOMException
from thug.DOM.W3C.DOMImplementation import DOMImplementation
from thug.DOM.W3C.Document import Document
from thug.DOM.W3C.DocumentFragment import DocumentFragment
from thug.DOM.W3C.DocumentType import DocumentType
from thug.DOM.W3C.Element import Element
from thug.DOM.W3C.NamedNodeMap import NamedNodeMap
from thug.DOM.W3C.Node import Node
from thug.DOM.W3C.NodeList import NodeList
from thug.DOM.W3C.ProcessingInstruction import ProcessingInstruction
from thug.DOM.W3C.Text import Text
from thug.DOM.W3C.HTML.HTMLAllCollection import HTMLAllCollection
from thug.DOM.W3C.HTML.HTMLAnchorElement import HTMLAnchorElement
from thug.DOM.W3C.HTML.HTMLAppletElement import HTMLAppletElement
from thug.DOM.W3C.HTML.HTMLBRElement import HTMLBRElement
from thug.DOM.W3C.HTML.HTMLBaseElement import HTMLBaseElement
from thug.DOM.W3C.HTML.HTMLBaseFontElement import HTMLBaseFontElement
from thug.DOM.W3C.HTML.HTMLBodyElement import HTMLBodyElement
from thug.DOM.W3C.HTML.HTMLButtonElement import HTMLButtonElement
from thug.DOM.W3C.HTML.HTMLCollection import HTMLCollection
from thug.DOM.W3C.HTML.HTMLDListElement import HTMLDListElement
from thug.DOM.W3C.HTML.HTMLDirectoryElement import HTMLDirectoryElement
from thug.DOM.W3C.HTML.HTMLDivElement import HTMLDivElement
from thug.DOM.W3C.HTML.HTMLDocument import HTMLDocument
from thug.DOM.W3C.HTML.HTMLDocumentCompatibleInfo import HTMLDocumentCompatibleInfo
from thug.DOM.W3C.HTML.HTMLElement import HTMLElement
from thug.DOM.W3C.HTML.HTMLFieldSetElement import HTMLFieldSetElement
from thug.DOM.W3C.HTML.HTMLFontElement import HTMLFontElement
from thug.DOM.W3C.HTML.HTMLFormElement import HTMLFormElement
from thug.DOM.W3C.HTML.HTMLFrameElement import HTMLFrameElement
from thug.DOM.W3C.HTML.HTMLFrameSetElement import HTMLFrameSetElement
from thug.DOM.W3C.HTML.HTMLHRElement import HTMLHRElement
from thug.DOM.W3C.HTML.HTMLHeadElement import HTMLHeadElement
from thug.DOM.W3C.HTML.HTMLHeadingElement import HTMLHeadingElement
from thug.DOM.W3C.HTML.HTMLHtmlElement import HTMLHtmlElement
from thug.DOM.W3C.HTML.HTMLIFrameElement import HTMLIFrameElement
from thug.DOM.W3C.HTML.HTMLImageElement import HTMLImageElement
from thug.DOM.W3C.HTML.HTMLInputElement import HTMLInputElement
from thug.DOM.W3C.HTML.HTMLIsIndexElement import HTMLIsIndexElement
from thug.DOM.W3C.HTML.HTMLLIElement import HTMLLIElement
from thug.DOM.W3C.HTML.HTMLLabelElement import HTMLLabelElement
from thug.DOM.W3C.HTML.HTMLLegendElement import HTMLLegendElement
from thug.DOM.W3C.HTML.HTMLLinkElement import HTMLLinkElement
from thug.DOM.W3C.HTML.HTMLMenuElement import HTMLMenuElement
from thug.DOM.W3C.HTML.HTMLMetaElement import HTMLMetaElement
from thug.DOM.W3C.HTML.HTMLModElement import HTMLModElement
from thug.DOM.W3C.HTML.HTMLOListElement import HTMLOListElement
from thug.DOM.W3C.HTML.HTMLObjectElement import HTMLObjectElement
from thug.DOM.W3C.HTML.HTMLOptGroupElement import HTMLOptGroupElement
from thug.DOM.W3C.HTML.HTMLOptionElement import HTMLOptionElement
from thug.DOM.W3C.HTML.HTMLOptionsCollection import HTMLOptionsCollection
from thug.DOM.W3C.HTML.HTMLParagraphElement import HTMLParagraphElement
from thug.DOM.W3C.HTML.HTMLParamElement import HTMLParamElement
from thug.DOM.W3C.HTML.HTMLPreElement import HTMLPreElement
from thug.DOM.W3C.HTML.HTMLQuoteElement import HTMLQuoteElement
from thug.DOM.W3C.HTML.HTMLScriptElement import HTMLScriptElement
from thug.DOM.W3C.HTML.HTMLSelectElement import HTMLSelectElement
from thug.DOM.W3C.HTML.HTMLStyleElement import HTMLStyleElement
from thug.DOM.W3C.HTML.HTMLTableCaptionElement import HTMLTableCaptionElement
from thug.DOM.W3C.HTML.HTMLTableCellElement import HTMLTableCellElement
from thug.DOM.W3C.HTML.HTMLTableColElement import HTMLTableColElement
from thug.DOM.W3C.HTML.HTMLTableElement import HTMLTableElement
from thug.DOM.W3C.HTML.HTMLTableRowElement import HTMLTableRowElement
from thug.DOM.W3C.HTML.HTMLTableSectionElement import HTMLTableSectionElement
from thug.DOM.W3C.HTML.HTMLTextAreaElement import HTMLTextAreaElement
from thug.DOM.W3C.HTML.HTMLTitleElement import HTMLTitleElement
from thug.DOM.W3C.HTML.HTMLUListElement import HTMLUListElement
from thug.DOM.W3C.Events.Event import Event
from thug.DOM.W3C.Events.EventTarget import EventTarget
from thug.DOM.W3C.Events.MouseEvent import MouseEvent
from thug.DOM.W3C.Events.MutationEvent import MutationEvent
from thug.DOM.W3C.Events.StorageEvent import StorageEvent
from thug.DOM.W3C.Events.UIEvent import UIEvent
from thug.DOM.W3C.Style.CSS.CSSStyleDeclaration import CSSStyleDeclaration


w3c_bindings = {
                'Attr'                       : Attr,
                'CDATASection'               : CDATASection,
                'CharacterData'              : CharacterData,
                'Comment'                    : Comment,
                'DOMException'               : DOMException,
                'DOMImplementation'          : DOMImplementation,
                'Document'                   : Document,
                'DocumentFragment'           : DocumentFragment,
                'DocumentType'               : DocumentType,
                'Element'                    : Element,
                'NamedNodeMap'               : NamedNodeMap,
                'Node'                       : Node,
                'NodeList'                   : NodeList,
                'ProcessingInstruction'      : ProcessingInstruction,
                'Text'                       : Text,
                'HTMLAllCollection'          : HTMLAllCollection,
                'HTMLAnchorElement'          : HTMLAnchorElement,
                'HTMLAppletElement'          : HTMLAppletElement,
                'HTMLBRElement'              : HTMLBRElement,
                'HTMLBaseElement'            : HTMLBaseElement,
                'HTMLBaseFontElement'        : HTMLBaseFontElement,
                'HTMLBodyElement'            : HTMLBodyElement,
                'HTMLButtonElement'          : HTMLButtonElement,
                'HTMLCollection'             : HTMLCollection,
                'HTMLDListElement'           : HTMLDListElement,
                'HTMLDirectoryElement'       : HTMLDirectoryElement,
                'HTMLDivElement'             : HTMLDivElement,
                'HTMLDocument'               : HTMLDocument,
                'HTMLDocumentCompatibleInfo' : HTMLDocumentCompatibleInfo,
                'HTMLElement'                : HTMLElement,
                'HTMLFieldSetElement'        : HTMLFieldSetElement,
                'HTMLFontElement'            : HTMLFontElement,
                'HTMLFormElement'            : HTMLFormElement,
                'HTMLFrameElement'           : HTMLFrameElement,
                'HTMLFrameSetElement'        : HTMLFrameSetElement,
                'HTMLHRElement'              : HTMLHRElement,
                'HTMLHeadElement'            : HTMLHeadElement,
                'HTMLHeadingElement'         : HTMLHeadingElement,
                'HTMLHtmlElement'            : HTMLHtmlElement,
                'HTMLIFrameElement'          : HTMLIFrameElement,
                'HTMLImageElement'           : HTMLImageElement,
                'HTMLInputElement'           : HTMLInputElement,
                'HTMLIsIndexElement'         : HTMLIsIndexElement,
                'HTMLLIElement'              : HTMLLIElement,
                'HTMLLabelElement'           : HTMLLabelElement,
                'HTMLLegendElement'          : HTMLLegendElement,
                'HTMLLinkElement'            : HTMLLinkElement,
                'HTMLMenuElement'            : HTMLMenuElement,
                'HTMLMetaElement'            : HTMLMetaElement,
                'HTMLModElement'             : HTMLModElement,
                'HTMLOListElement'           : HTMLOListElement,
                'HTMLObjectElement'          : HTMLObjectElement,
                'HTMLOptGroupElement'        : HTMLOptGroupElement,
                'HTMLOptionElement'          : HTMLOptionElement,
                'HTMLOptionsCollection'      : HTMLOptionsCollection,
                'HTMLParagraphElement'       : HTMLParagraphElement,
                'HTMLParamElement'           : HTMLParamElement,
                'HTMLPreElement'             : HTMLPreElement,
                'HTMLQuoteElement'           : HTMLQuoteElement,
                'HTMLScriptElement'          : HTMLScriptElement,
                'HTMLSelectElement'          : HTMLSelectElement,
                'HTMLStyleElement'           : HTMLStyleElement,
                'HTMLTableCaptionElement'    : HTMLTableCaptionElement,
                'HTMLTableCellElement'       : HTMLTableCellElement,
                'HTMLTableColElement'        : HTMLTableColElement,
                'HTMLTableElement'           : HTMLTableElement,
                'HTMLTableRowElement'        : HTMLTableRowElement,
                'HTMLTableSectionElement'    : HTMLTableSectionElement,
                'HTMLTextAreaElement'        : HTMLTextAreaElement,
                'HTMLTitleElement'           : HTMLTitleElement,
                'HTMLUListElement'           : HTMLUListElement,
                'Event'                      : Event,
                'EventTarget'                : EventTarget,
                'MouseEvent'                 : MouseEvent,
                'MutationEvent'              : MutationEvent,
                'StorageEvent'               : StorageEvent,
                'UIEvent'                    : UIEvent,
                'CSSStyleDeclaration'        : CSSStyleDeclaration,
                }
