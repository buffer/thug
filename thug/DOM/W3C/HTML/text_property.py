#!/usr/bin/env python

# import bs4 as BeautifulSoup

import logging
log = logging.getLogger("Thug")


def text_property(readonly = False):
    def getter(self):
        return str(self.tag.string) if self.tag.string else ""

    def setter(self, text):
        # if self.tag.string:
        #    self.tag.contents[0] = BeautifulSoup.NavigableString(text)
        # else:
        #    self.tag.append(text)
        #
        # self.tag.string = self.tag.contents[0]
        self.tag.string = text
        if self.tagName.lower() in ('script', ):
            if log.ThugOpts.code_logging:
                log.ThugLogging.add_code_snippet(text, 'Javascript', 'Contained_Inside')

            self.doc.window.evalScript(text, self.tag.string)

    return property(getter) if readonly else property(getter, setter)
