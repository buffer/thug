#!/usr/bin/env python

import sys
import re
import string
import os
import bs4 as BeautifulSoup

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir)))

try:
    from io import StringIO
except ImportError:
    try:
        from cStringIO import StringIO
    except ImportError:
        from StringIO import StringIO

from .HTMLCollection import HTMLCollection
from .attr_property import attr_property

def xpath_property(xpath, readonly = False):
    RE_INDEXED = re.compile("(\w+)\[([^\]]+)\]")
    
    parts = xpath.split('/')
    
    def getChildren(tag, parts, recursive = False):
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

        tags = tag.find_all(name, recursive = recursive)

        if idx:
            if idx[0] == '@':
                tags = [tag for tag in tags if tag.has_attr(idx[1:])]
            else:
                tags = [tags[int(idx)-1]]
        
        for child in tags:
            children += getChildren(child, parts[1:])
            
        return children
        
    def getter(self):
        children = getChildren(self.doc, parts)

        if xpath == '/html/body[1]' and not children:
            children = [self.doc]

        if parts[-1] == 'text()':
            return "".join(children)

        m = RE_INDEXED.match(parts[-1])

        if m:
            try:
                from DOMImplementation import DOMImplementation
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
                    child = BeautifulSoup.Tag(parser = self.doc, name = part)
                    
                    tag.append(child)
                    
                tag = child
                
        tag.append(value)

    return property(getter) if readonly else property(getter, setter)

