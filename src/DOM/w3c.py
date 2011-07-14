#!/usr/bin/env python
from __future__ import with_statement

import sys, re, string

try:
    from urllib.parse import urlparse # Python 3
except ImportError:
    from urlparse import urlparse

try:
    from io import StringIO # Python 3
except ImportError:
    try:
        from cStringIO import StringIO
    except ImportError:
        from StringIO import StringIO

import logging
import BeautifulSoup
import PyV8

class abstractmethod(object):
    def __init__(self, func):
        self.func = func

    def __call__(self, *args, **kwds):
        raise NotImplementedError("method %s is abstract." % self.func.func_name)

class DOMException(RuntimeError, PyV8.JSClass):
    def __init__(self, code):
        self.code = code

    # ExceptionCode
    INDEX_SIZE_ERR                 = 1  # If index or size is negative, or greater than the allowed value
    DOMSTRING_SIZE_ERR             = 2  # If the specified range of text does not fit into a DOMString
    HIERARCHY_REQUEST_ERR          = 3  # If any node is inserted somewhere it doesn't belong
    WRONG_DOCUMENT_ERR             = 4  # If a node is used in a different document than the one that created it (that doesn't support it)
    INVALID_CHARACTER_ERR          = 5  # If an invalid or illegal character is specified, such as in a name. 
    NO_DATA_ALLOWED_ERR            = 6  # If data is specified for a node which does not support data
    NO_MODIFICATION_ALLOWED_ERR    = 7  # If an attempt is made to modify an object where modifications are not allowed
    NOT_FOUND_ERR                  = 8  # If an attempt is made to reference a node in a context where it does not exist
    NOT_SUPPORTED_ERR              = 9  # If the implementation does not support the type of object requested
    INUSE_ATTRIBUTE_ERR            = 10 # If an attempt is made to add an attribute that is already in use elsewhere    
    
class Node(PyV8.JSClass):
    # NodeType
    ELEMENT_NODE                   = 1
    ATTRIBUTE_NODE                 = 2
    TEXT_NODE                      = 3
    CDATA_SECTION_NODE             = 4
    ENTITY_REFERENCE_NODE          = 5
    ENTITY_NODE                    = 6
    PROCESSING_INSTRUCTION_NODE    = 7
    COMMENT_NODE                   = 8
    DOCUMENT_NODE                  = 9
    DOCUMENT_TYPE_NODE             = 10
    DOCUMENT_FRAGMENT_NODE         = 11
    NOTATION_NODE                  = 12
    
    def __init__(self, doc):
        self.doc = doc        
        
    def __repr__(self):
        return "<Node %s at 0x%08X>" % (self.nodeName, id(self))
                
    def __eq__(self, other):
        return hasattr(other, "doc") and self.doc == other.doc
        
    def __ne__(self, other):
        return not self.__eq__(other)
    
    @property
    @abstractmethod
    def nodeType(self):
        pass
    
    @property
    @abstractmethod
    def nodeName(self):
        pass
    
    @abstractmethod
    def getNodeValue(self):
        return None
    
    @abstractmethod
    def setNodeValue(self, value):
        raise DOMException(DOMException.NO_MODIFICATION_ALLOWED_ERR)
    
    nodeValue = property(getNodeValue, setNodeValue)
    
    @property
    def attributes(self):
        return None
    
    @property
    def childNodes(self):
        return NodeList(self.doc, [])
        
    @property
    def firstChild(self):
        return None
            
    @property
    def lastChild(self):
        return None
            
    @property
    def nextSibling(self):
        return None
            
    @property
    def previousSibling(self):
        return None
            
    @property
    def parentNode(self):
        return None
    
    @property
    def ownerDocument(self):
        return self.doc
    
    def insertBefore(self, newChild, refChild):
        raise DOMException(DOMException.HIERARCHY_REQUEST_ERR)

    def insertAfter(self, newChild, refChild):
        raise DOMException(DOMException.HIERARCHY_REQUEST_ERR)

    def replaceChild(self, newChild, oldChild):
        raise DOMException(DOMException.HIERARCHY_REQUEST_ERR)
    
    def removeChild(self, oldChild):
        raise DOMException(DOMException.NOT_FOUND_ERR)
    
    def appendChild(self, newChild):
        raise DOMException(DOMException.HIERARCHY_REQUEST_ERR)
    
    def hasChildNodes(self):
        return False
    
    @abstractmethod
    def cloneNode(self, deep):
        pass
    
    @staticmethod
    def wrap(doc, obj):
        if obj is None:
            return None
        
        if type(obj) == BeautifulSoup.CData:
            return CDATASection(doc, obj)
        
        if type(obj) == BeautifulSoup.NavigableString:
            return Text(doc, obj)        
        
        return Element(doc, obj)
    
class NodeList(PyV8.JSClass):
    def __init__(self, doc, nodes):
        self.doc = doc
        self.nodes = nodes
        
    def __len__(self):
        return self.length
        
    def __getitem__(self, key):
        return self.item(int(key))
    
    def item(self, index):
        return DOMImplementation.createHTMLElement(self.doc, self.nodes[index]) if 0 <= index and index < len(self.nodes) else None
    
    @property
    def length(self):
        return len(self.nodes)

class NamedNodeMap(PyV8.JSClass):
    def __init__(self, parent):        
        self.parent = parent
        
    def getNamedItem(self, name):
        return self.parent.getAttributeNode(name)
    
    def setNamedItem(self, attr):
        oldattr = self.parent.getAttributeNode(attr.name)
        
        attr.parent = self.parent
        
        self.parent.tag[attr.name] = attr.value
        
        if oldattr:
            oldattr.parent = None
        
        return oldattr
    
    def removeNamedItem(self, name):
        self.parent.removeAttribute(name)
    
    def item(self, index):
        names = self.parent.tag.attrMap.keys()
        return self.parent.getAttributeNode(names[index]) if 0 <= index and index < len(names) else None
    
    @property
    def length(self):        
        return len(self.parent.tag._getAttrMap()) 
        
class Attr(Node):
    _value = ""
    
    def __init__(self, parent, attr):
        self.parent = parent
        self.attr = attr
        
        self._value = self.getValue()
        
    def __repr__(self):
        return "<Attr object %s%s at 0x%08X>" % ("%s." % self.parent.tagName if self.parent else "", self.attr, id(self))
        
    def __eq__(self, other):
        return hasattr(other, "parent") and self.parent == other.parent and \
               hasattr(other, "attr") and self.attr == other.attr
        
    @property
    def nodeType(self):
        return Node.ATTRIBUTE_NODE
       
    @property        
    def nodeName(self):
        return self.attr
    
    def getNodeValue(self):
        return self.getValue()
    
    def setNodeValue(self, value):
        return self.setValue(value)
        
    nodeValue = property(getNodeValue, setNodeValue)
    
    @property
    def childNodes(self):
        return NodeList(self.parent.doc, [])
    
    @property
    def parentNode(self):
        return self.parent
        
    @property
    def ownerDocument(self):
        return self.parent.doc
    
    @property
    def name(self):
        return self.attr
    
    def specified(self):
        return self.parent.has_key(self.attr)
    
    def getValue(self):
        if self.parent:
            if self.parent.tag.has_key(self.attr):
                return self.parent.tag[self.attr]
            
        return self._value 
        
    def setValue(self, value):
        self._value = value
        
        if self.parent:
            self.parent.tag[self.attr] = value
        
    value = property(getValue, setValue)
    
class Element(Node):
    def __init__(self, doc, tag):
        Node.__init__(self, doc)
        
        self.tag = tag

    def __str__(self):
        return str(self.tag)

    def __unicode__(self):
        return unicode(self.tag)
        
    def __repr__(self):
        return "<Element %s at 0x%08X>" % (self.tag.name, id(self))
        
    def __eq__(self, other):
        return Node.__eq__(self, other) and hasattr(other, "tag") and self.tag == other.tag

    @property
    def nodeType(self):
        return Node.ELEMENT_NODE
       
    @property
    def nodeName(self):
        return self.tagName
    
    @property
    def nodeValue(self):
        return None
    
    @property
    def attributes(self):
        return NamedNodeMap(self)    
    
    @property
    def parentNode(self):
        return self.tag.parent
    
    @property
    def childNodes(self):
        return NodeList(self.doc, self.tag.contents)
        
    @property
    def firstChild(self):
        return Node.wrap(self.doc, self.tag.contents[0]) if len(self.tag) > 0 else None
            
    @property
    def lastChild(self):
        return Node.wrap(self.doc, self.tag.contents[-1]) if len(self.tag) > 0 else None
            
    @property
    def nextSibling(self):
        return Node.wrap(self.doc, self.tag.nextSibling)
            
    @property
    def previousSibling(self):
        return Node.wrap(self.doc, self.tag.previousSibling)
        
    def checkChild(self, child):
        if not isinstance(child, Node):
            raise DOMException(DOMException.HIERARCHY_REQUEST_ERR)            
        
    def findChild(self, child):
        try:
            return self.tag.contents.index(child.tag)
        except ValueError:
            return -1
        
    def insertBefore(self, newChild, refChild):        
        self.checkChild(newChild)
        self.checkChild(refChild)
        
        index = self.findChild(refChild)        
        
        if index < 0:
            self.tag.append(newChild.tag)            
        else:        
            self.tag.insert(index, newChild.tag)
        
        return newChild

    def insertAfter(self, newChild, refChild):
        self.checkChild(newChild)
        self.checkChild(refChild)

        index = self.findChild(refChild)

        if index < 0:
            self.tag.append(newChild.tag)
        else:
            self.tag.insert(index+1, newChild.tag)

        return newChild

    def replaceChild(self, newChild, oldChild):
        self.checkChild(newChild)
        self.checkChild(oldChild)
        
        index = self.findChild(oldChild)
        
        if index < 0:
            raise DOMException(DOMException.NOT_FOUND_ERR)
            
        self.tag.contents[index] = newChild.tag
        
        return oldChild
    
    def removeChild(self, oldChild):
        self.checkChild(oldChild)
        
        self.tag.contents.remove(oldChild.tag)
        
        return oldChild
    
    def appendChild(self, newChild):
        if newChild:            
            if isinstance(newChild, Text):            
                self.tag.append(str(newChild))
            else:
                self.checkChild(newChild)
                
                self.tag.append(newChild.tag)
            
        return newChild
    
    def hasChildNodes(self):
        return len(self.tag.contents) > 0
    
    @property
    def tagName(self):
        return self.tag.name.upper()
    
    def getAttribute(self, name):
        return self.tag[name] if self.tag.has_key(name) else ""
        
    def setAttribute(self, name, value):
        self.tag[name] = value
        
    def removeAttribute(self, name):
        del self.tag[name]
        
    def getAttributeNode(self, name):
        return Attr(self, name) if self.tag.has_key(name) else None
    
    def setAttributeNode(self, attr):
        self.tag[attr.name] = attr.value
    
    def removeAttributeNode(self, attr):
        del self.tag[attr.name]
    
    def getElementsByTagName(self, name):
        return NodeList(self.doc, self.tag.findAll(name))
    
    def normalize(self):
        pass

class CharacterData(Node):
    def __init__(self, doc, tag):
        Node.__init__(self, doc)
        
        self.tag = tag
        
    def __str__(self):
        return str(self.tag)
        
    def getData(self):
        return unicode(self.tag)
        
    def setData(self, data):
        raise DOMException(DOMException.NO_MODIFICATION_ALLOWED_ERR)
        
    data = property(getData, setData)

    @property
    def length(self):
        return len(self.tag)
        
    def substringData(self, offset, count):
        return self.tag[offset:offset+count]
        
    def appendData(self, arg):
        raise DOMException(DOMException.NO_MODIFICATION_ALLOWED_ERR)
        
    def insertData(self, offset, arg):
        raise DOMException(DOMException.NO_MODIFICATION_ALLOWED_ERR)
        
    def deleteData(self, offset, count):
        raise DOMException(DOMException.NO_MODIFICATION_ALLOWED_ERR)
        
    def replaceData(self, offset, count, arg):
        raise DOMException(DOMException.NO_MODIFICATION_ALLOWED_ERR)

class Text(CharacterData):
    def __repr__(self):
        return "<Text '%s' at 0x%08X>" % (self.tag, id(self))
    
    def splitText(self, offset):
        raise DOMException(DOMException.NO_MODIFICATION_ALLOWED_ERR)

    @property
    def nodeValue(self):
        return self.data

    @property
    def nodeName(self):
        return "#text"

class CDATASection(Text):
    def __repr__(self):
        return "<CDATA '%s' at 0x%08X>" % (self.tag, id(self))

    @property 
    def nodeName(self):
        return "#cdata-section"

class Comment(CharacterData):
    @property
    def nodeName(self):
        return "#comment"

class DocumentFragment(Node):
    def __init__(self, doc, tags):
        Node.__init__(self, doc)
        
        self.tags = tags

    @property
    def nodeName(self):
        return "#document-fragment"

class DocumentType(Node):
    RE_DOCTYPE = re.compile("^DOCTYPE (\w+)", re.M + re.S)
    
    def __init__(self, doc, tag):
        Node.__init__(self, doc)
        
        self.parse(tag)
        
    def parse(self, text):
        m = self.RE_DOCTYPE.match(text)
        
        self._name = m.group(1) if m else ""
        
    @property
    def name(self):
        return self._name

    @property
    def nodeName(self):
        return self._name
    
    @property
    def entities(self):
        raise NotImplementedError()
    
    @property
    def notations(self):
        raise NotImplementedError()
    
class Notation(Node):
    @property
    def publicId(self):
        pass
    
    @property
    def systemId(self):
        pass

    @property
    def nodeName(self):
        pass
    
class Entity(Node):
    @property
    def publicId(self):
        pass
    
    @property
    def systemId(self):
        pass
    
    @property
    def notationName(self):
        pass

    @property
    def nodeName(self):
        pass
    
class EntityReference(Node):
    def __init__(self, doc, name):
        Node.__init__(self, doc)
        
        self.name = name
        
    def nodeName(self):
        return self.name
    
class ProcessingInstruction(Node):
    def __init__(self, doc, target, data):
        self._target = target
        self.data = data
        
    @property
    def target(self):
        return self._target

    @property
    def nodeName(self):
        return self._target

class Document(Node):
    def __str__(self):
        return str(self.doc)

    def __unicode__(self):
        return unicode(self.doc)

    def __repr__(self):
        return "<Document at 0x%08X>" % id(self)

    @property
    def nodeType(self):
        return Node.DOCUMENT_NODE
    
    @property
    def nodeName(self):
        return "#document"
    
    @property
    def nodeValue(self):
        return None
    
    @property
    def childNodes(self):
        return NodeList(self.doc, self.doc.contents)
        
    @property
    def doctype(self):
        for tag in self.doc:
            if isinstance(tag, BeautifulSoup.Declaration) and tag.startswith("DOCTYPE"):
                return DocumentType(self.doc, tag)
                
        return None
    
    @property
    def implementation(self):
        return self
    
    @property
    def documentElement(self):        
        return Element(self, self.doc.find('html'))
        
    onCreateElement = None
    
    def createElement(self, tagname):        
        element = DOMImplementation.createHTMLElement(self.doc, BeautifulSoup.Tag(self.doc, tagname))
        
        if self.onCreateElement:
            self.onCreateElement(element)
        
        return element
    
    def createDocumentFragment(self):
        return DocumentFragment(self)
    
    def createTextNode(self, data):
        return Text(self, BeautifulSoup.NavigableString(data))
    
    def createComment(self, data):
        return Comment(self, data)
    
    def createCDATASection(self, data):
        return CDATASection(self, data)
    
    def createProcessingInstruction(self, target, data):
        return ProcessingInstruction(self, target, data)
    
    def createAttribute(self, name):
        return Attr(None, name)
    
    def createEntityReference(self, name):
        return EntityReference(self, name)
    
    def getElementsByTagName(self, tagname):
        return NodeList(self.doc, self.doc.findAll(tagname.lower()))
        
def attr_property(name, attrtype=str, readonly=False, default=None):
    def getter(self):
        return attrtype(self.tag[name]) if self.tag.has_key(name) else default
        
    def setter(self, value):
        self.tag[name] = attrtype(value)
        
    return property(getter) if readonly else property(getter, setter)
        
def text_property(readonly=False):
    def getter(self):
        return str(self.tag.string)
    
    def setter(self, text):
        if self.tag.string:
            self.tag.contents[0] = BeautifulSoup.NavigableString(text)
        else:
            self.tag.append(text)
                    
        self.tag.string = self.tag.contents[0]
        
    return property(getter) if readonly else property(getter, setter)
        
class HTMLCollection(PyV8.JSClass):
    def __init__(self, doc, nodes):
        self.doc = doc
        self.nodes = nodes
        
    def __len__(self):
        return self.length
        
    def __getitem__(self, key):        
        try:
            return self.item(int(key))
        except TypeError:
            return self.namedItem(str(key))        
        
    @property
    def length(self):
        return len(self.nodes)
    
    def item(self, index):
        node = self.nodes[index]
                
        return DOMImplementation.createHTMLElement(self.doc, node) if node else None
    
    def namedItem(self, name):
        for node in self.nodes:
            if node.nodeName == name:
                return DOMImplementation.createHTMLElement(self.doc, node) if node else None
            
        return None
    
class CSSStyleDeclaration(object):
    def __init__(self, style):
        self.props = dict([prop.strip().split(': ') for prop in style.split(';') if prop])
        
        for k, v in self.props.items():
            if v and v[0] == v[-1] and v[0] in ['"', "'"]:
                self.props[k] = v[1:-1]                
        
    @property
    def cssText(self):
        return '; '.join(["%s: %s" % (k, v) for k, v in self.props.items()])
        
    def getPropertyValue(self, name):
        return self.props.get(name, '')
        
    def removeProperty(self, name):
        v = self.props.get(name, '')
        
        if v:
            del self.props[name]
            
        return v
    
    @property
    def length(self):
        return len(self.props)
        
    def item(self, index):
        if type(index) == str:
            return self.props.get(index, '')
        
        if index < 0 or index >= len(self.props):
            return ''
        
        return self.props[self.props.keys()[index]]
        
    def __getattr__(self, name):
        if hasattr(object, name):
            return object.__getattribute__(self, name)
        else:
            return object.__getattribute__(self, 'props').get(name, '')
        
    def __setattr__(self, name, value):
        if name == 'props':
            object.__setattr__(self, name, value)
        else:
            object.__getattribute__(self, 'props')[name] = value
    
class ElementCSSInlineStyle(object):
    @property
    def style(self):
        return CSSStyleDeclaration(self.tag['style'] if self.tag.has_key('style') else '')

class HTMLElement(Element, ElementCSSInlineStyle):    
    id = attr_property("id")
    title = attr_property("title")
    lang = attr_property("lang")
    dir = attr_property("dir")
    className = attr_property("class")    
    innerHTML = text_property()

class HTMLHtmlElement(HTMLElement):
    version = attr_property("version")
    
class HTMLHeadElement(HTMLElement):
    profile = attr_property("profile")
    
class HTMLLinkElement(HTMLElement):
    disabled = False
    
    charset = attr_property("charset")
    href = attr_property("href")
    hreflang = attr_property("hreflang")
    media = attr_property("media")
    rel = attr_property("rel")
    rev = attr_property("rev")
    target = attr_property("target")
    type = attr_property("type")
    
class HTMLTitleElement(HTMLElement):
    text = text_property()
    
class HTMLMetaElement(HTMLElement):
    content = attr_property("content")
    httpEquiv = attr_property("http-equiv")
    name = attr_property("name")
    scheme = attr_property("scheme")
    
class HTMLBaseElement(HTMLElement):
    href = attr_property("href")
    target = attr_property("target")
    
class HTMLIsIndexElement(HTMLElement):
    form = None
    prompt = attr_property("prompt")
    
class HTMLStyleElement(HTMLElement):
    disabled = False
    
    media = attr_property("media")
    type = attr_property("type")
    
class HTMLBodyElement(HTMLElement):
    background = attr_property("background")
    bgColor = attr_property("bgcolor")
    link = attr_property("link")
    aLink = attr_property("alink")
    vLink = attr_property("vlink")
    text = attr_property("text")
    
class HTMLFormElement(HTMLElement):
    @property
    def elements(self):
        raise NotImplementedError()
    
    @property
    def length(self):
        raise NotImplementedError()
    
    name = attr_property("name")
    acceptCharset = attr_property("accept-charset", default="UNKNOWN")
    action = attr_property("action")
    enctype = attr_property("enctype", default="application/x-www-form-urlencoded")
    method = attr_property("method", default="get")
    target = attr_property("target")
    
    def submit(self):
        raise NotImplementedError()
    
    def reset(self):
        raise NotImplementedError()
    
class HTMLSelectElement(HTMLElement):
    @property
    def type(self):
        raise NotImplementedError()
        
    selectedIndex = 0
    value = None
    
    @property
    def length(self):
        raise NotImplementedError()
        
    @property
    def form(self):
        raise NotImplementedError()
        
    @property
    def options(self):
        raise NotImplementedError()
        
    disabled = attr_property("disabled", bool)
    multiple = attr_property("multiple", bool)    
    name = attr_property("name")
    size = attr_property("size", long)
    tabIndex = attr_property("tabindex", long)
    
    def add(self, element, before):
        raise NotImplementedError()
        
    def remove(self, index):
        raise NotImplementedError()
        
    def blur(self):
        raise NotImplementedError()

    def focus(self):
        raise NotImplementedError()
        
class HTMLOptGroupElement(HTMLElement):
    disabled = attr_property("disabled", bool)    
    label = attr_property("label")
    
class HTMLOptionElement(HTMLElement):
    @property
    def form(self):
        raise NotImplementedError()
        
    defaultSelected = attr_property("selected", bool)    
    text = text_property(readonly=True)    
    index = attr_property("index", long)
    disabled = attr_property("disabled", bool)    
    label = attr_property("label")
    selected = False
    value = attr_property("value")
    
class HTMLInputElement(HTMLElement):    
    defaultValue = attr_property("value")
    defaultChecked = attr_property("checked")
    
    @property
    def form(self):
        raise NotImplementedError()
    
    accept = attr_property("accept")
    accessKey = attr_property("accesskey")
    align = attr_property("align")
    alt = attr_property("alt")
    checked = attr_property("checked", bool)
    disabled = attr_property("disabled", bool)
    maxLength = attr_property("maxlength", long, default=sys.maxint)
    name = attr_property("name")
    readOnly = attr_property("readonly", bool)
    size = attr_property("size")
    src = attr_property("src")
    tabIndex = attr_property("tabindex", long)
    type = attr_property("type", readonly=True, default="text")
    useMap = attr_property("usermap")
    
    @abstractmethod
    def getValue(self):
        pass
    
    @abstractmethod
    def setValue(self, value):
        pass
    
    value = property(getValue, setValue)
    
    def blur(self):
        pass
    
    def focus(self):
        pass
    
    def select(self):
        pass
    
    def click(self):
        pass
    
class HTMLTextAreaElement(HTMLElement):
    defaultValue = None
    
    @property
    def form(self):
        pass
    
    accessKey = attr_property("accesskey")
    cols = attr_property("cols", long)
    disabled = attr_property("disabled", bool)
    name = attr_property("name")
    readOnly = attr_property("readonly", bool)
    rows = attr_property("rows", long)
    tabIndex = attr_property("tabindex", long)
    value = text_property()
    
    @property
    def type(self):
        return "textarea"
    
class HTMLButtonElement(HTMLElement):
    @property
    def form(self):
        pass    
    
    accessKey = attr_property("accesskey")
    disabled = attr_property("disabled", bool)
    name = attr_property("name")
    tabIndex = attr_property("tabindex", long)
    type = attr_property("type")
    value = attr_property("value")
    
class HTMLAppletElement(HTMLElement):
    align = attr_property("align")
    alt = attr_property("alt")
    archive = attr_property("archive")
    code = attr_property("code")
    codeBase = attr_property("codebase")
    height = attr_property("height")
    hspace = attr_property("hspace")
    name = attr_property("name")
    object = attr_property("object")
    vspace = attr_property("vspace")
    width = attr_property("width")
    
class HTMLImageElement(HTMLElement):
    align = attr_property("align")
    alt = attr_property("alt")
    border = attr_property("border")
    height = attr_property("height")
    hspace = attr_property("hspace")
    isMap = attr_property("ismap")
    longDesc = attr_property("longdesc")
    lowSrc = attr_property("lowsrc")
    name = attr_property("name")
    src = attr_property("src")
    useMap = attr_property("usemap")
    vspace = attr_property("vspace")
    width = attr_property("width")
    
class HTMLScriptElement(HTMLElement):
    text = text_property()    
    htmlFor = None
    event = None
    charset = attr_property("charset")
    defer = attr_property("defer", bool)
    src = attr_property("src")
    type = attr_property("type")
    
class HTMLFrameSetElement(HTMLElement):
    cols = attr_property("cols")
    rows = attr_property("rows")

class HTMLFrameElement(HTMLElement):
    frameBorder = attr_property("frameborder")
    longDesc = attr_property("longdesc")
    marginHeight = attr_property("marginheight")
    marginWidth = attr_property("marginwidth")
    name = attr_property("name")
    noResize = attr_property("noresize", bool)
    scrolling = attr_property("scrolling")
    src = attr_property("src")
    
class HTMLIFrameElement(HTMLElement):
    align = attr_property("align")
    frameBorder = attr_property("frameborder")
    height = attr_property("height")
    longDesc = attr_property("longdesc")
    marginHeight = attr_property("marginheight")
    marginWidth = attr_property("marginwidth")
    name = attr_property("name")    
    scrolling = attr_property("scrolling")
    src = attr_property("src")
    width = attr_property("width")

def xpath_property(xpath, readonly=False):
    RE_INDEXED = re.compile("(\w+)\[([^\]]+)\]")
    
    parts = xpath.split('/')
    
    def getChildren(tag, parts, recursive=False):
        if len(parts) == 0:
            return [tag]
        
        part = parts[0]
        
        if part == '':
            return getChildren(tag, parts[1:], True)
            
        if part == 'text()':
            return [tag.string]
        
        m = RE_INDEXED.match(part)
        
        if m:
            name = m.group(1)
            idx = m.group(2)
        else:
            name = part
            idx = None

        children = []

        tags = tag.findAll(name, recursive=recursive)

        if idx:
            if idx[0] == '@':
                tags = [tag for tag in tags if tag.has_key(idx[1:])]
            else:
                tags = [tags[int(idx)-1]]
        
        for child in tags:
            children += getChildren(child, parts[1:])
            
        return children
        
    def getter(self):
        children = getChildren(self.doc, parts)
        
        if parts[-1] == 'text()':
            return "".join(children)

        m = RE_INDEXED.match(parts[-1])

        if m:
            try:
                string.atoi(m.group(2))

                return DOMImplementation.createHTMLElement(self.doc, children[0]) if len(children) > 0 else None
            except ValueError: 
                pass
                
        return HTMLCollection(self.doc, children)
        
    def setter(self, value):
        tag = self.doc
        
        for part in parts:
            if part == '':
                continue
            elif part == 'text()':
                if tag.string:
                    tag.contents[0] = BeautifulSoup.NavigableString(value)
                else:
                    tag.append(value)                    
                    
                tag.string = tag.contents[0]

                return
            else:
                child = tag.find(part)
                
                if not child:
                    child = BeautifulSoup.Tag(self.doc, part)
                    
                    tag.append(child)
                    
                tag = child
                
        tag.append(value)

    return property(getter) if readonly else property(getter, setter)

class HTMLDocument(Document):
    title = xpath_property("/html/head/title/text()")
    body = xpath_property("/html/body[1]")

    images = xpath_property("//img", readonly=True)
    applets = xpath_property("//applet", readonly=True)
    forms = xpath_property("//form", readonly=True)
    links = xpath_property("//a[@href]", readonly=True)
    anchors = xpath_property("//a[@name]", readonly=True)
    innerHTML = text_property()

    def __init__(self, doc, win=None, referer=None, lastModified=None, cookie=''):
        Document.__init__(self, doc)

        self._win = win
        self._referer = referer
        self._lastModified = lastModified
        self._cookie = cookie

        self._html = None

        self.current = None

    @property
    def window(self):
        return self._win

    @window.setter
    def window(self, win):
        self._win = win

    @property
    def referrer(self):
        return self._referer

    @property
    def lastModified(self):
        return self._lastModified

    @property
    def cookie(self):
        return self._cookie
        
    @property
    def domain(self):
        return urlparse(self._win.url).hostname if self._win else ''
        
    @property
    def URL(self):
        return self._win.url if self._win else ''

    def open(self, mimetype='text/html', replace=False):
        self._html = StringIO()

        return self
    
    def close(self):
        html = self._html.getvalue()
        self._html.close()
        self._html = None

        self.doc = BeautifulSoup.BeautifulSoup(html)

    def write(self, html):
        if self._html:
            self._html.write(html)
        else:
            tag = self.current
            parent = tag.parent
            pos = parent.contents.index(tag) + 1

            for tag in BeautifulSoup.BeautifulSoup(html).contents:
                parent.insert(pos, tag)

                pos += 1

    def writeln(self, text):
        self.write(text + "\n")
    
    def getElementById(self, elementId):
        tag = self.doc.find(id=elementId)
        return DOMImplementation.createHTMLElement(self.doc, tag) if tag else None

    def getElementsByName(self, elementName):
        tags = self.doc.findAll(attrs={'name': elementName})
        
        return HTMLCollection(self.doc, tags)

class DOMImplementation(HTMLDocument):
    def hasFeature(self, feature, version):
        return feature == "HTML" and version == "1.0"
        
    TAGS = {
        "html" : HTMLHtmlElement,
        "head" : HTMLHeadElement,
        "link" : HTMLLinkElement,
        "title" : HTMLTitleElement,
        "meta" : HTMLMetaElement,
        "base" : HTMLBaseElement,
        "isindex" : HTMLIsIndexElement,
        "style" : HTMLStyleElement,
        "body" : HTMLBodyElement,
        "form" : HTMLFormElement,
        "select" : HTMLSelectElement,
        "optgroup" : HTMLOptGroupElement,
        "option" : HTMLOptionElement,
        "input" : HTMLInputElement,
        "textarea" : HTMLTextAreaElement,
        "button" : HTMLButtonElement,
        "applet" : HTMLAppletElement,
        "img" : HTMLImageElement,
        "script" : HTMLScriptElement,
        "frameset" : HTMLFrameSetElement,
        "frame" : HTMLFrameElement,
        "iframe" : HTMLIFrameElement,
    }
        
    @staticmethod
    def createHTMLElement(doc, tag):        
        if DOMImplementation.TAGS.has_key(tag.name.lower()):            
            return DOMImplementation.TAGS[tag.name.lower()](doc, tag)
        else:
            return HTMLElement(doc, tag)
    
def getDOMImplementation(dom=None, **kwds):
    return DOMImplementation(dom if dom else BeautifulSoup.BeautifulSoup(), **kwds)
    
def parseString(html, **kwds):
    return DOMImplementation(BeautifulSoup.BeautifulSoup(html), **kwds)
    
def parse(file, **kwds):
    if isinstance(file, StringTypes):
        with open(file, 'r') as f:
            return parseString(f.read())
    
    return parseString(file.read(), **kwds)
    
import unittest

TEST_HTML = """
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
                      "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
    <head>
        <!-- This is a comment -->
        <title>this is a test</title>
        <script type="text/javascript"> 
        //<![CDATA[
        function load()
        {
            alert("load");
        }
        function unload()
        {
            alsert("unload");
        }
        //]]>
        </script>         
    </head>
    <body onload="load()" onunload="unload()">
        <p id="hello">Hello World!</p>
        <form name="first"></form>
        <form name="second"></form>
        <a href="#">link</a>
        <a name="#">anchor</a>
    </body>
</html>"""

class DocumentTest(unittest.TestCase):
    def setUp(self):
        self.doc = parseString(TEST_HTML)
        
        self.assert_(self.doc)
        
    def testNode(self):
        self.assertEquals(Node.DOCUMENT_NODE, self.doc.nodeType)
        self.assertEquals("#document", self.doc.nodeName)
        self.failIf(self.doc.nodeValue)
        
        html = self.doc.documentElement
        
        self.assert_(html)        
        self.assertEquals(Node.ELEMENT_NODE, html.nodeType)
        self.assertEquals("HTML", html.nodeName)
        self.failIf(html.nodeValue)
        
        attr = html.getAttributeNode("xmlns")
        
        self.assert_(attr)

        self.assertEquals(Node.ATTRIBUTE_NODE, attr.nodeType)
        self.assertEquals("xmlns", attr.nodeName)
        self.assertEquals("http://www.w3.org/1999/xhtml", attr.nodeValue)
        
    def testNodeList(self):
        nodes = self.doc.getElementsByTagName("body")
        
        self.assertEquals(1, nodes.length)
        
        self.assert_(nodes.item(0))
        self.failIf(nodes.item(-1))
        self.failIf(nodes.item(1))

        self.assertEquals(1, len(nodes))

        self.assert_(nodes[0])
        self.failIf(nodes[-1])
        self.failIf(nodes[1])

    def testDocument(self):
        nodes = self.doc.getElementsByTagName("body")
        
        body = nodes.item(0)
        
        self.assertEquals("BODY", body.tagName)   
    
    def testDocumentType(self):
        doctype = self.doc.doctype
        
        self.assert_(doctype)
        
        self.assertEquals("html", doctype.name)
                
    def testElement(self):
        html = self.doc.documentElement
        
        self.assertEquals("HTML", html.tagName)
        self.assertEquals("http://www.w3.org/1999/xhtml", html.getAttribute("xmlns"))
        self.assert_(html.getAttributeNode("xmlns"))
        
        nodes = html.getElementsByTagName("body")
        
        self.assertEquals(1, nodes.length)
        
        body = nodes.item(0)
        
        self.assertEquals("BODY", body.tagName)
        
        div = self.doc.createElement("div")
        
        self.assert_(div)
        self.failIf(div.hasChildNodes())
        self.assertEquals(0, len(div.childNodes))
        
        a = self.doc.createElement("a")
        b = self.doc.createElement("b")
        p = self.doc.createElement("p")
        
        self.assert_(a == div.appendChild(a))
        self.assert_(div.hasChildNodes())
        self.assertEquals(1, len(div.childNodes))        
        self.assert_(a == div.childNodes[0])
        
        self.assert_(b == div.insertBefore(b, a))
        self.assertEquals(2, len(div.childNodes))
        self.assert_(b == div.childNodes[0])
        self.assert_(a == div.childNodes[1])
        
        self.assert_(a == div.replaceChild(p, a))
        self.assertEquals(2, len(div.childNodes))
        self.assert_(b == div.childNodes[0])
        self.assert_(p == div.childNodes[1])
        
        self.assert_(b == div.removeChild(b))
        self.assertEquals(1, len(div.childNodes))        
        self.assert_(p == div.childNodes[0])
        
        self.assertRaises(DOMException, div.appendChild, "hello")
        self.assertRaises(DOMException, div.insertBefore, "hello", p)
        self.assertRaises(DOMException, div.replaceChild, "hello", p)
        self.assertRaises(DOMException, div.removeChild, "hello")
        
    def testAttr(self):
        html = self.doc.documentElement
        
        attr = html.getAttributeNode("xmlns")
        
        self.assert_(attr)
        
        self.assertEquals(html, attr.parentNode)
        self.failIf(attr.hasChildNodes())        
        self.assert_(attr.childNodes != None)
        self.assertEquals(0, attr.childNodes.length)
        self.failIf(attr.firstChild)
        self.failIf(attr.lastChild)
        self.failIf(attr.previousSibling)
        self.failIf(attr.nextSibling)
        self.failIf(attr.attributes)
        
        self.assertFalse(attr.hasChildNodes())        
        
        self.assertEquals(self.doc, attr.ownerDocument)

        self.assertEquals("xmlns", attr.name)        
        self.assert_(True, attr.specified)
        
        self.assertEquals("http://www.w3.org/1999/xhtml", attr.value)
        
        attr.value = "test"
        
        self.assertEquals("test", attr.value)
        self.assertEquals("test", html.getAttribute("xmlns"))
        
        body = html.getElementsByTagName("body").item(0)
        
        self.assert_(body)
        
        onload = body.getAttributeNode("onload")
        onunload = body.getAttributeNode("onunload")
        
        self.assert_(onload)
        self.assert_(onunload)

    def testNamedNodeMap(self):
        attrs = self.doc.getElementsByTagName("body").item(0).attributes
        
        self.assert_(attrs)
        
        self.assertEquals(2, attrs.length)
        
        attr = attrs.getNamedItem("onload")
        
        self.assert_(attr)        
        self.assertEquals("onload", attr.name)
        self.assertEquals("load()", attr.value)
        
        attr = attrs.getNamedItem("onunload")
        
        self.assert_(attr)        
        self.assertEquals("onunload", attr.name)
        self.assertEquals("unload()", attr.value)
        
        self.failIf(attrs.getNamedItem("nonexists"))
        
        self.failIf(attrs.item(-1))
        self.failIf(attrs.item(attrs.length))
        
        for i in xrange(attrs.length):
            self.assert_(attrs.item(i))
            
        attr = self.doc.createAttribute("hello")
        attr.value = "world"
        
        self.assert_(attr)
        
        self.failIf(attrs.setNamedItem(attr))
        self.assertEquals("world", attrs.getNamedItem("hello").value)
        
        attr.value = "flier"
        
        self.assertEquals("flier", attrs.getNamedItem("hello").value)
        
        attrs.getNamedItem("hello").value = "world"
        
        self.assertEquals("world", attr.value)
        
        old = attrs.setNamedItem(self.doc.createAttribute("hello"))
        
        self.assert_(old)
        self.assertEquals(old.name, attr.name)
        self.assertEquals(old.value, attr.value)
        
        self.assertNotEquals(old, attr)
        
        self.assertEquals(attr, attrs.getNamedItem("hello"))
        
        attrs.getNamedItem("hello").value = "flier"
        
        self.assertEquals("flier", attrs.getNamedItem("hello").value)
        self.assertEquals("flier", attr.value)
        self.assertEquals("world", old.value)
        self.failIf(old.parent)

class HTMLDocumentTest(unittest.TestCase):
    def setUp(self):
        self.doc = parseString(TEST_HTML)
        
        self.assert_(self.doc)
        
    def testHTMLElement(self):
        p = self.doc.getElementById('hello')
        
        self.assert_(p)
        
        self.assertEquals('hello', p.id)
        
        p.id = 'test'
        
        self.assertEquals(p, self.doc.getElementById('test'))
        
        forms = self.doc.getElementsByName('first')
        
        self.assertEquals(1, len(forms))
        
    def testDocument(self):
        self.assertEquals("this is a test", self.doc.title)
        
        self.doc.title = "another title"
        
        self.assertEquals("another title", self.doc.title)
        
        doc = parseString("<html></html>")
        
        self.failIf(doc.title)
        
        doc.title = "another title"        
        
        self.assertEquals("another title", doc.title)        
        
        self.assertEquals(self.doc.getElementsByTagName('body')[0], self.doc.body)
        
        forms = self.doc.forms
        
        self.assert_(forms != None)
        self.assertEquals(2, len(forms))
        
        self.assert_(isinstance(forms[0], HTMLFormElement))
        self.assertEquals("first", forms[0].name)
        self.assertEquals("second", forms[1].name)

        self.assertEquals(1, len(self.doc.links))
        self.assertEquals(1, len(self.doc.anchors))

    def testWrite(self):
        self.assertEquals("this is a test", self.doc.title)

        doc = self.doc.open()
        doc.write("<html><head><title>Hello World</title></head><body></body></html>")
        doc.close()

        self.assertEquals("Hello World", doc.title)

        doc.current = doc.getElementsByTagName('title')[0].tag
        doc.write("<meta/>")

        self.assertEquals("<head><title>Hello World</title><meta /></head>", str(doc.getElementsByTagName('head')[0]))
        
class CSSStyleDeclarationTest(unittest.TestCase):
    def testParse(self):
        style = 'width: "auto"; border: "none"; font-family: "serif"; background: "red"'
        
        css = CSSStyleDeclaration(style)
        
        self.assert_(css)
        self.assertEquals('width: auto; font-family: serif; border: none; background: red', css.cssText)
        self.assertEquals(4, css.length)
        
        self.assertEquals('auto', css.getPropertyValue('width'))
        self.assertEquals('', css.getPropertyValue('height'))
        
        self.assertEquals('auto', css.item(0))
        self.assertEquals('auto', css.width)
        
        css.width = 'none'
        
        self.assertEquals('none', css.getPropertyValue('width'))
        self.assertEquals('none', css.item(0))
        self.assertEquals('none', css.width)

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG if "-v" in sys.argv else logging.WARN,
                        format='%(asctime)s %(levelname)s %(message)s')
    
    unittest.main()
