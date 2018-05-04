#!/usr/bin/env python

from thug.DOM.JSClass import JSClass


class ClassList(JSClass):
    def __init__(self, tag):
        self.__init_class_list(tag)

    def __init_class_list(self, tag):
        self._class_list = list()

        for t in tag.find_all():
            if 'class' not in t.attrs:
                continue

            c = t.attrs['class']
            if c in self._class_list:
                continue

            self._class_list.append(c)

    def add(self, c):
        if c not in self._class_list:
            self._class_list.append(c)

    def remove(self, c):
        if c not in self._class_list:
            return

        self._class_list.remove(c)

    def item(self, index):
        if index < 0 or index > len(self._class_list) - 1:
            return None

        return self._class_list[index - 1]

    def toggle(self, c, force = False):
        if c in self._class_list:
            self.remove(c)
            return False

        self.add(c)
        return True

    def contains(self, c):
        return c in self._class_list

    def replace(self, oldClass, newClass):
        if oldClass not in self._class_list:
            return

        self.remove(oldClass)
        self.add(newClass)
