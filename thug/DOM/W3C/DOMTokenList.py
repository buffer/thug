#!/usr/bin/env python

import logging

log = logging.getLogger("Thug")

class DOMTokenList:
    def __init__(self, supported, tokens = None):
        self.tokens = [] if tokens is None else tokens
        self.__init_supported(supported)

    def __init_supported(self, supported):
        self.supported = []

        for support in supported:
            if support not in self.supported:
                self.supported.append(support)

            nosupport = f"no{support}"
            if nosupport not in self.supported:
                self.supported.append(nosupport)

    @property
    def length(self):
        return len(self.tokens)

    def item(self, index):
        return self.tokens[index] if index in range(0, len(self.tokens)) else None

    def contains(self, token):
        return token in self.tokens

    def add(self, token):
        if token in self.supported and token not in self.tokens:
            self.tokens.append(token)

    def remove(self, token):
        if token in self.tokens:
            self.tokens.remove(token)

    def toggle(self, token):
        if token in self.tokens:
            self.tokens.remove(token)
            return

        self.tokens.append(token)

    def replace(self, oldToken, newToken):
        self.remove(oldToken)
        self.add(newToken)

    def supports(self, token):
        return token in self.supported

    @property
    def value(self):
        return " ".join(self.tokens)
