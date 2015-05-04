# Microsoft XMLDOM

import bs4 as BeautifulSoup
from DOM.W3C import w3c
from OS.Windows import security_sys
from DOM.W3C.NamedNodeMap import NamedNodeMap

import logging
log = logging.getLogger("Thug")

def loadXML(self, bstrXML):
    self.xml = w3c.parseString(bstrXML)
    #self.attributes = NamedNodeMap(self.xml._node)

    if "res://" not in bstrXML:
        return

    for p in bstrXML.split('"'):
        if p.startswith("res://"):
            log.ThugLogging.add_behavior_warn("[Microsoft XMLDOM ActiveX] Attempting to load %s" % (p, ))
            if any(sys.lower() in p.lower() for sys in security_sys):
                self.parseError._errorCode = 0

    for p in bstrXML.split("'"):
        if p.startswith("res://"):
            log.ThugLogging.add_behavior_warn("[Microsoft XMLDOM ActiveX] Attempting to load %s" % (p, ))
            if any(sys.lower() in p.lower() for sys in security_sys):
                self.parseError._errorCode = 0
