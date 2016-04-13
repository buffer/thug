try:
    from io import StringIO
except ImportError:
    try:
        from cStringIO import StringIO
    except ImportError:
        from StringIO import StringIO

import logging
from Magic.Magic import Magic
log = logging.getLogger("Thug")

def open(self):
    log.ThugLogging.add_behavior_warn("[Adodb.Stream ActiveX] open")
    self.fobject = StringIO()

def Write(self, s):
    log.ThugLogging.add_behavior_warn("[Adodb.Stream ActiveX] Write")
    self.fobject.write(unicode(s))

def SaveToFile(self, filename, opt):
    log.ThugLogging.add_behavior_warn("[Adodb.Stream ActiveX] SaveToFile (%s)" % (filename, ))
    log.ThugLogging.log_exploit_event(self._window.url,
                                      "Adodb.Stream ActiveX",
                                      "SaveToFile",
                                      data = {
                                                "file": filename
                                             },
                                      forward = False)

    content = self.fobject.getvalue()
    mtype = Magic(content).get_mime()

    log.ThugLogging.log_file(
        content,
        url=filename,
        sampletype=mtype,
    )

def Close(self):
    log.ThugLogging.add_behavior_warn("[Adodb.Stream ActiveX] Close")
    self.fobject.close()
