#!/usr/bin/env python

import re
import string
import bs4 as BeautifulSoup

from .HTMLCollection import HTMLCollection

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

        _tags = tag.find_all(name, recursive = recursive)

        if idx:
            if idx[0] == '@':
                tags = [t for t in _tags if t.has_attr(idx[1:])]
            else:
                tags = [_tags[int(idx)-1]]
        else:
            tags = _tags

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
                from thug.DOM.W3C.DOMImplementation import DOMImplementation
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
