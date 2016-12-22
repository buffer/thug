# Microsoft Rich Textbox Control 6.0 (SP6)
# CVE-NOMATCH

import logging

log = logging.getLogger("Thug")


def SaveFile(self, path, arg):
    log.ThugLogging.add_behavior_warn("[Microsoft Rich Textbox Control ActiveX] Writing to file %s" % (str(path), ))
    log.ThugLogging.add_behavior_warn("[Microsoft Rich Textbox Control ActiveX] Content: \n%s" % (str(self.Text), ))
    log.ThugLogging.log_exploit_event(self._window.url,
                                      "Microsoft Rich Textbox Control ActiveX",
                                      "Writing file",
                                      data = {
                                                "file"   : str(path),
                                                "content": str(self.Text)
                                             },
                                      forward = False)
