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


import thug.DOM.W3C.Core as Core
import thug.DOM.W3C.HTML as HTML
import thug.DOM.W3C.Events as Events

from thug.DOM.W3C.Style.CSS.CSSStyleDeclaration import CSSStyleDeclaration


w3c_bindings = {
                'Attr'                       : Core.Attr,
                'CDATASection'               : Core.CDATASection,
                'CharacterData'              : Core.CharacterData,
                'Comment'                    : Core.Comment,
                'DOMException'               : Core.DOMException,
                # 'DOMImplementation'          : Core.DOMImplementation,
                'Document'                   : Core.Document,
                'DocumentFragment'           : Core.DocumentFragment,
                'DocumentType'               : Core.DocumentType,
                'Element'                    : Core.Element,
                'NamedNodeMap'               : Core.NamedNodeMap,
                'Node'                       : Core.Node,
                'NodeList'                   : Core.NodeList,
                'ProcessingInstruction'      : Core.ProcessingInstruction,
                'Text'                       : Core.Text,
                'HTMLAllCollection'          : HTML.HTMLAllCollection,
                'HTMLAnchorElement'          : HTML.HTMLAnchorElement,
                'HTMLAppletElement'          : HTML.HTMLAppletElement,
                'HTMLBRElement'              : HTML.HTMLBRElement,
                'HTMLBaseElement'            : HTML.HTMLBaseElement,
                'HTMLBaseFontElement'        : HTML.HTMLBaseFontElement,
                'HTMLBodyElement'            : HTML.HTMLBodyElement,
                'HTMLButtonElement'          : HTML.HTMLButtonElement,
                'HTMLCollection'             : HTML.HTMLCollection,
                'HTMLDListElement'           : HTML.HTMLDListElement,
                'HTMLDirectoryElement'       : HTML.HTMLDirectoryElement,
                'HTMLDivElement'             : HTML.HTMLDivElement,
                'HTMLDocument'               : HTML.HTMLDocument,
                'HTMLDocumentCompatibleInfo' : HTML.HTMLDocumentCompatibleInfo,
                'HTMLElement'                : HTML.HTMLElement,
                'HTMLFieldSetElement'        : HTML.HTMLFieldSetElement,
                'HTMLFontElement'            : HTML.HTMLFontElement,
                'HTMLFormElement'            : HTML.HTMLFormElement,
                'HTMLFrameElement'           : HTML.HTMLFrameElement,
                'HTMLFrameSetElement'        : HTML.HTMLFrameSetElement,
                'HTMLHRElement'              : HTML.HTMLHRElement,
                'HTMLHeadElement'            : HTML.HTMLHeadElement,
                'HTMLHeadingElement'         : HTML.HTMLHeadingElement,
                'HTMLHtmlElement'            : HTML.HTMLHtmlElement,
                'HTMLIFrameElement'          : HTML.HTMLIFrameElement,
                'HTMLImageElement'           : HTML.HTMLImageElement,
                'HTMLInputElement'           : HTML.HTMLInputElement,
                'HTMLIsIndexElement'         : HTML.HTMLIsIndexElement,
                'HTMLLIElement'              : HTML.HTMLLIElement,
                'HTMLLabelElement'           : HTML.HTMLLabelElement,
                'HTMLLegendElement'          : HTML.HTMLLegendElement,
                'HTMLLinkElement'            : HTML.HTMLLinkElement,
                'HTMLMediaElement'           : HTML.HTMLMediaElement,
                'HTMLMenuElement'            : HTML.HTMLMenuElement,
                'HTMLMetaElement'            : HTML.HTMLMetaElement,
                'HTMLModElement'             : HTML.HTMLModElement,
                'HTMLOListElement'           : HTML.HTMLOListElement,
                'HTMLObjectElement'          : HTML.HTMLObjectElement,
                'HTMLOptGroupElement'        : HTML.HTMLOptGroupElement,
                'HTMLOptionElement'          : HTML.HTMLOptionElement,
                'HTMLOptionsCollection'      : HTML.HTMLOptionsCollection,
                'HTMLParagraphElement'       : HTML.HTMLParagraphElement,
                'HTMLParamElement'           : HTML.HTMLParamElement,
                'HTMLPreElement'             : HTML.HTMLPreElement,
                'HTMLQuoteElement'           : HTML.HTMLQuoteElement,
                'HTMLScriptElement'          : HTML.HTMLScriptElement,
                'HTMLSelectElement'          : HTML.HTMLSelectElement,
                'HTMLSpanElement'            : HTML.HTMLSpanElement,
                'HTMLStyleElement'           : HTML.HTMLStyleElement,
                'HTMLTableCaptionElement'    : HTML.HTMLTableCaptionElement,
                'HTMLTableCellElement'       : HTML.HTMLTableCellElement,
                'HTMLTableColElement'        : HTML.HTMLTableColElement,
                'HTMLTableElement'           : HTML.HTMLTableElement,
                'HTMLTableRowElement'        : HTML.HTMLTableRowElement,
                'HTMLTableSectionElement'    : HTML.HTMLTableSectionElement,
                'HTMLTextAreaElement'        : HTML.HTMLTextAreaElement,
                'HTMLTitleElement'           : HTML.HTMLTitleElement,
                'HTMLUListElement'           : HTML.HTMLUListElement,
                'Event'                      : Events.Event,
                'EventTarget'                : Events.EventTarget,
                'MouseEvent'                 : Events.MouseEvent,
                'MutationEvent'              : Events.MutationEvent,
                'StorageEvent'               : Events.StorageEvent,
                'UIEvent'                    : Events.UIEvent,
                'CSSStyleDeclaration'        : CSSStyleDeclaration,
                }
