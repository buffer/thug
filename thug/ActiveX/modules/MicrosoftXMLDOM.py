# Microsoft XMLDOM
from lxml import etree

import base64
import binascii
from thug.DOM.W3C import w3c
from thug.OS.Windows import security_sys
# from DOM.W3C.NamedNodeMap import NamedNodeMap

import logging
log = logging.getLogger("Thug")


class Node(etree.ElementBase):
    def __init__(self, elementName):
        self._nodeTypedValue = None
        self._dataType = None
        etree.ElementBase.__init__(elementName)

    def getNodeTypedValue(self):
        try:
            if self._dataType == 'bin.base64':
                return base64.b64decode(self.text)
            elif self._dataType == 'bin.hex':
                return binascii.unhexlify(self.text)
        except:  # pylint:disable=bare-except
            pass

        return self.text

    def setNodeTypedValue(self, value):
        try:
            if self.dataType == 'bin.base64':
                self.text = base64.b64encode(value)
            elif self.dataType == 'bin.hex':
                self.text = binascii.hexlify(value)
            else:
                self.text = value
        except:  # pylint:disable=bare-except
            self.text = value

    nodeTypedValue = property(getNodeTypedValue, setNodeTypedValue)

    def getDataType(self):
        return self._dataType

    def setDataType(self, value):
        self._dataType = value

    dataType = property(getDataType, setDataType)


def loadXML(self, bstrXML):
    self.xml = w3c.parseString(bstrXML)
    # self.attributes = NamedNodeMap(self.xml._node)

    if "res://" not in bstrXML:
        return

    for p in bstrXML.split('"'):
        if p.startswith("res://"):
            log.URLClassifier.classify(p)
            log.ThugLogging.add_behavior_warn("[Microsoft XMLDOM ActiveX] Attempting to load %s" % (p, ))
            if any(sys.lower() in p.lower() for sys in security_sys):
                self.parseError._errorCode = 0

    for p in bstrXML.split("'"):
        if p.startswith("res://"):
            log.URLClassifier.classify(p)
            log.ThugLogging.add_behavior_warn("[Microsoft XMLDOM ActiveX] Attempting to load %s" % (p, ))
            if any(sys.lower() in p.lower() for sys in security_sys):
                self.parseError._errorCode = 0


def createElement(self, bstrTagName):
    log.ThugLogging.add_behavior_warn("[Microsoft XMLDOM ActiveX] Creating element %s" % (bstrTagName, ))
    return Node(bstrTagName)
