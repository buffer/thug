# Microsoft Rich Textbox Control 6.0 (SP6)
# CVE-NOMATCH

import logging
log = logging.getLogger("Thug")

def SaveFile(self, path, arg):
    log.ThugLogging.add_behavior_warn("[Microsoft Rich Textbox Control ActiveX] Writing to file % s" % (str(path), ))
    log.ThugLogging.add_behavior_warn("[Microsoft Rich Textbox Control ActiveX] Content: \n%s" % (str(self.Text), ))

