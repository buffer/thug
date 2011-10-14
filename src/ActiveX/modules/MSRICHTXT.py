# Microsoft Rich Textbox Control 6.0 (SP6)
# CVE-NOMATCH

import logging
log = logging.getLogger("Thug.ActiveX")

def SaveFile(self, path, arg):
    log.warning("Microsoft Rich Textbox Control ActiveX writing to file % s" % (str(path), ))
    log.warning("Content: \n%s" % (str(self.Text), ))

