#!/usr/bin/env python

import sys
import re
import string
import logging
import site

import bs4 as BeautifulSoup
from .DOMImplementation import DOMImplementation

def getDOMImplementation(dom = None, **kwds):
    return DOMImplementation(dom if dom else BeautifulSoup.BeautifulSoup(), **kwds)
    
def parseString(html, **kwds):
    return DOMImplementation(BeautifulSoup.BeautifulSoup(html, "html5lib"), **kwds)
    
def parse(file, **kwds):
    if isinstance(file, StringTypes):
        with open(file, 'r') as f:
            return parseString(f.read())
    
    return parseString(file.read(), **kwds)


import unittest
from .DOMException import DOMException
from .Node import Node
from .HTML.HTMLFormElement import HTMLFormElement
from .Style.CSS.CSSStyleDeclaration import CSSStyleDeclaration

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
            alert("unload");
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

        self.assertEquals(True, html.isSupported("HTML", "1.0"))
        self.assertEquals(True, html.isSupported("HTML", "2.0"))
        self.assertEquals(False, html.isSupported("HTML", "3.0"))
        
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
        self.assertRaises(DOMException, self.doc.createEvent, 'foo')
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
        self.assertEquals(True, body.hasAttributes())
        self.assertEquals(True, body.hasAttribute("onload"))
        self.assertEquals(True, body.hasAttribute("onunload"))
        self.assertEquals(False, body.hasAttribute("onmouseover"))

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

        self.assertEquals('<p id="test">Hello World!</p>' +
                          '<form name="first"></form>' +
                          '<form name="second"></form>' +
                          '<a href="#">link</a>' +
                          '<a name="#">anchor</a>',
                          self.doc.getElementsByTagName('body')[0].innerHTML)
        self.assertEquals("Hello World!", p.innerHTML)
        self.assertEquals("", self.doc.getElementsByTagName('form')[0].innerHTML)

        self.assertEquals(None, self.doc.getElementById('inner'))

        self.doc.getElementsByTagName('form')[0].innerHTML = "<div id='inner'/>"

        self.assertEquals('DIV', self.doc.getElementById('inner').tagName)
        
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
