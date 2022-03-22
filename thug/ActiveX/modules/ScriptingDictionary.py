import logging

log = logging.getLogger("Thug")


def Add(self, key, item):
    msg = f'[Scripting.Dictionary ActiveX] Add("{key}", "{item}")'
    log.ThugLogging.add_behavior_warn(msg)

    if key not in self.dictionary:
        self.Count += 1

    self.dictionary[key] = item

def Exists(self, key):
    return key in self.dictionary

def Items(self):
    msg = '[Scripting.Dictionary ActiveX] Items()'
    log.ThugLogging.add_behavior_warn(msg)

    return list(self.dictionary.values())

def Keys(self):
    msg = '[Scripting.Dictionary ActiveX] Keys()'
    log.ThugLogging.add_behavior_warn(msg)

    return list(self.dictionary.keys())

def Remove(self, key):
    msg = f'[Scripting.Dictionary ActiveX] Remove("{key}")'
    log.ThugLogging.add_behavior_warn(msg)

    if key in self.dictionary:
        del self.dictionary[key]
        self.Count -= 1

def RemoveAll(self):
    msg = '[Scripting.Dictionary ActiveX] RemoveAll()'
    log.ThugLogging.add_behavior_warn(msg)

    self.dictionary.clear()
    self.Count = 0
