import logging

log = logging.getLogger("Thug")


def Add(self, value):
    self.arraylist.append(value)
    return self.arraylist.index(value)


def ToArray(self):
    return list(self.arraylist)
