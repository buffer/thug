# HP Info Center ActiveX Control
# CVE-2007-6331, CVE-2007-6332, CVE-2007-6333


def LaunchApp(prog, args, unk):
    add_alert("HP Info Center LaunchApp called to run: " + prog + " " + args)
	
def SetRegValue(key, section, keyname, value):
    add_alert("HP Info Center SetRegValue: " + str(key) + "/" + str(section) + "/" + str(keyname) + " set to " + str(value))

def GetRegValue(key, section, keyname):
    add_alert("HP Info Center GetRegValue, reading: " + key + "/" + section + "/" + keyname)

def EvaluateRules():
    add_alert("HP Info Center EvaluateRules")

def SaveToFile(path):
    print "HP Software Update SaveToFile(), writes to " + path
    add_alert("HP Software Update SaveToFile(), writes to " + path)

def ProcessRegistryData(parm):
    add_alert("HP Info Center ProcessRegistryData: " + parm)

self.LaunchApp = LaunchApp
self.SetRegValue = SetRegValue
self.GetRegValue = GetRegValue
self.EvaluateRules = EvaluateRules
self.SaveToFile = SaveToFile
self.ProcessRegistryData = ProcessRegistryData
