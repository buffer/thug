#!/usr/bin/env python
from __future__ import with_statement

import sys, re, string

from HTML import BeautifulSoup
import PyV8
import logging
import urlparse

from Node import Node
from Text import Text
from DOMException import DOMException

log = logging.getLogger("Thug")


def handle_hcp(s):
    log.warning('Microsoft Internet Explorer HCP Scheme Detected')

    hcp = s.path.split('svr=')
    if len(hcp) < 2:
        return

    hcp = hcp[1].split('defer>')
    if len(hcp) < 2:
        return

    hcp = hcp[1].split('</script')
    if not hcp:
        return

    log.warning('Microsoft Internet Explorer HCP Exploit Detected')
    return hcp[0]


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
        from NamedNodeMap import NamedNodeMap
        return NamedNodeMap(self)    
    
    @property
    def parentNode(self):
        return self.tag.parent
    
    @property
    def childNodes(self):
        from NodeList import NodeList
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
  
    # Introduced in DOM Level 2
    def hasAttributes(self):
        return self.attributes.length > 0

    # Introduced in DOM Level 2
    def hasAttribute(self, name):
        return self.tag.has_key(name)
        
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
              
                # FIXME
                self.tag.append(newChild.tag)
                #self.tag.append(str(newChild))

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

        if name in ('src', 'code'):
            s = urlparse.urlsplit(value)

            if s.scheme == 'hcp':
                hcp = handle_hcp(s)
                if hcp:
                    self.doc.window.evalScript(hcp) 
                return

            response, content = self.doc.window._navigator.fetch(value)
        
    def removeAttribute(self, name):
        del self.tag[name]
        
    def getAttributeNode(self, name):
        from Attr import Attr
        
        return Attr(self, name) if self.tag.has_key(name) else None
    
    def setAttributeNode(self, attr):
        self.tag[attr.name] = attr.value
    
    def removeAttributeNode(self, attr):
        del self.tag[attr.name]
    
    def getElementsByTagName(self, name):
        from NodeList import NodeList

        return NodeList(self.doc, self.tag.findAll(name))
   
    # DOM Level 2 Core [Appendix A]
    # The method normalize is now inherited from the Node interface where
    # it was moved
    #
    #def normalize(self):
    #    pass

