#!/usr/bin/env python

import logging

from thug.DOM.JSClass import JSClass

log = logging.getLogger("Thug")


class ClassList(JSClass):
    def __init__(self, tag):
        self.tag = tag
        self.__init_classlist_personality()
        self.__init_class_list()

    def __init_classlist_personality(self):
        if log.ThugOpts.Personality.isIE():
            self.__init_classlist_personality_IE()
            return

        if log.ThugOpts.Personality.isFirefox():
            self.__init_classlist_personality_Firefox()
            return

        if log.ThugOpts.Personality.isChrome():
            self.__init_classlist_personality_Chrome()
            return

        if log.ThugOpts.Personality.isSafari():
            self.__init_classlist_personality_Safari()
            return

    def __init_classlist_personality_IE(self):
        self.add = self.__add_ie
        self.remove = self.__remove_ie
        self.toggle = self.__toggle_ie

    def __init_classlist_personality_Firefox(self):
        self.add = self.__add
        self.remove = self.__remove
        self.toggle = self.__toggle
        self.replace = self.__replace

    def __init_classlist_personality_Chrome(self):
        self.add = self.__add
        self.remove = self.__remove
        self.toggle = self.__toggle
        self.replace = self.__replace

    def __init_classlist_personality_Safari(self):
        self.add = self.__add
        self.remove = self.__remove
        self.toggle = self.__toggle

    def __init_class_list(self):
        self._class_list = list()

        if 'class' not in self.tag.attrs:
            return

        for c in self.tag.attrs['class'].split():
            if c not in self._class_list:
                self._class_list.append(c)

    def __do_add(self, c):
        if c not in self._class_list:
            self._class_list.append(c)

        if 'class' not in self.tag.attrs:
            self.tag.attrs['class'] = c
            return

        attrs = self.tag.attrs['class'].split()
        if c in attrs:
            return

        attrs.append(c)
        self.tag.attrs['class'] = " ".join(attrs)

    def __add(self, *args):
        for c in args:
            self.__do_add(c)

    def __add_ie(self, c):
        self.__do_add(c)

    def __do_remove(self, c):
        if c in self._class_list:
            self._class_list.remove(c)

        if 'class' not in self.tag.attrs:
            return

        attrs = self.tag.attrs['class'].split()
        if c not in attrs:
            return

        attrs.remove(c)
        self.tag.attrs['class'] = " ".join(attrs)

    def __remove(self, *args):
        for c in args:
            self.__do_remove(c)

    def __remove_ie(self, c):
        self.__do_remove(c)

    def item(self, index):
        if index < 0 or index > len(self._class_list) - 1:
            return None

        return self._class_list[index]

    def __toggle(self, c, force = None):
        if force is False or c in self._class_list:
            self.remove(c)
            return False

        self.add(c)
        return True

    def __toggle_ie(self, c):
        return self.__toggle(c)

    def contains(self, c):
        return c in self._class_list

    def __replace(self, oldClass, newClass):
        if oldClass not in self._class_list:
            return

        self.remove(oldClass)
        self.add(newClass)
