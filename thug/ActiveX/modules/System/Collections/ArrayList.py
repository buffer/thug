import logging

log = logging.getLogger("Thug")


def Add(self, value):
    log.ThugLogging.add_behavior_warn("[System.Collections.ArrayList] Add")
    self.arraylist.append(value)
    return self.arraylist.index(value)


def ToArray(self):
    log.ThugLogging.add_behavior_warn("[System.Collections.ArrayList] ToArray")
    return list(self.arraylist)
