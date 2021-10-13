# Microsoft Rich Textbox Control 6.0 (SP6)
# CVE-NOMATCH

import logging

log = logging.getLogger("Thug")


def SaveFile(self, path, arg): # pylint:disable=unused-argument
    log.ThugLogging.add_behavior_warn(f"[Microsoft Rich Textbox Control ActiveX] Writing to file {str(path)}")
    log.ThugLogging.add_behavior_warn(f"[Microsoft Rich Textbox Control ActiveX] Content: \n{str(self.Text)}")
    log.ThugLogging.log_exploit_event(self._window.url,
                                      "Microsoft Rich Textbox Control ActiveX",
                                      "Writing file",
                                      data = {
                                                "file"   : str(path),
                                                "content": str(self.Text)
                                             },
                                      forward = False)
