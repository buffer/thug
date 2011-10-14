# HP Info Center ActiveX Control
# CVE-2007-6331, CVE-2007-6332, CVE-2007-6333

import logging
log = logging.getLogger("Thug.ActiveX")

def LaunchApp(self, prog, args, unk):
    log.warning("HP Info Center LaunchApp called to run: %s %s" % (prog, args, ))
	
def SetRegValue(self, key, section, keyname, value):
    log.warning("HP Info Center SetRegValue: %s/%s/%s set to %s" % (str(key), str(section), str(keyname), str(value), ))

def GetRegValue(self, key, section, keyname):
    log.warning("HP Info Center GetRegValue, reading: %s/%s/%s" % (key, section, keyname, ))

def EvaluateRules(self):
    log.warning("HP Info Center EvaluateRules")

def SaveToFile(self, path):
    log.warning("HP Software Update SaveToFile(), writes to %s" % (path, ))

def ProcessRegistryData(self, parm):
    log.warning("HP Info Center ProcessRegistryData: %s " % (parm, ))

