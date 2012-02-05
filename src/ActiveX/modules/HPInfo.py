# HP Info Center ActiveX Control
# CVE-2007-6331, CVE-2007-6332, CVE-2007-6333

import logging
log = logging.getLogger("Thug")

def LaunchApp(self, prog, args, unk):
    log.MAEC.add_behavior_warn("HP Info Center LaunchApp called to run: %s %s" % (prog, args, ), 
                               "CVE-2007-6331")
	
def SetRegValue(self, key, section, keyname, value):
    log.MAEC.add_behavior_warn("HP Info Center SetRegValue: %s/%s/%s set to %s" % (str(key), 
                                                                                   str(section), 
                                                                                   str(keyname), 
                                                                                   str(value), ),
                               "CVE-2007-6332")

def GetRegValue(self, key, section, keyname):
    log.MAEC.add_behavior_warn("HP Info Center GetRegValue, reading: %s/%s/%s" % (str(key), 
                                                                                  str(section), 
                                                                                  str(keyname), ),
                               "CVE-2007-6333")

def EvaluateRules(self):
    log.MAEC.add_behavior_warn("HP Info Center EvaluateRules")

def SaveToFile(self, path):
    log.MAEC.add_behavior_warn("HP Software Update SaveToFile(), writes to %s" % (path, ))

def ProcessRegistryData(self, parm):
    log.MAEC.add_behavior_warn("HP Info Center ProcessRegistryData: %s " % (parm, ))

