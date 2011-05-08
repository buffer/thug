# HP Info Center ActiveX Control
# CVE-2007-6331, CVE-2007-6332, CVE-2007-6333


def LaunchApp(prog, args, unk):
    add_alert("HP Info Center LaunchApp called to run: %s %s" % (prog, args, ))
	
def SetRegValue(key, section, keyname, value):
    add_alert("HP Info Center SetRegValue: %s/%s/%s set to %s" % (str(key), str(section), str(keyname), str(value), ))

def GetRegValue(key, section, keyname):
    add_alert("HP Info Center GetRegValue, reading: %s/%s/%s" % (key, section, keyname, ))

def EvaluateRules():
    add_alert("HP Info Center EvaluateRules")

def SaveToFile(path):
    add_alert("HP Software Update SaveToFile(), writes to %s" % (path, ))
    add_alert("HP Software Update SaveToFile(), writes to %s" % (path, ))

def ProcessRegistryData(parm):
    add_alert("HP Info Center ProcessRegistryData: %s " % (parm, ))


self.LaunchApp           = LaunchApp
self.SetRegValue         = SetRegValue
self.GetRegValue         = GetRegValue
self.EvaluateRules       = EvaluateRules
self.SaveToFile          = SaveToFile
self.ProcessRegistryData = ProcessRegistryData
