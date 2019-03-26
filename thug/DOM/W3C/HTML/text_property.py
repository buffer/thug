#!/usr/bin/env python

import logging

log = logging.getLogger("Thug")


def text_property(readonly = False):
    def getter(self):
        return str(self.tag.string) if self.tag.string else ""

    def setter(self, text):
        self.tag.string = text

        if self.tagName.lower() in ('script', ):
            if log.ThugOpts.code_logging:
                log.ThugLogging.add_code_snippet(text, 'Javascript', 'Contained_Inside')

            script_type = self.tag.attrs.get('type', None)
            if script_type and 'vbscript' in script_type.lower():
                log.VBSClassifier.classify(log.ThugLogging.url if log.ThugOpts.local else log.last_url, text)

            self.doc.window.evalScript(text, self.tag.string)

    return property(getter) if readonly else property(getter, setter)
