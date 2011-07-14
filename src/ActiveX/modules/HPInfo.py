# HP Info Center ActiveX Control
# CVE-2007-6331, CVE-2007-6332, CVE-2007-6333

acct = ActiveXAcct[self]

def LaunchApp(prog, args, unk):
    global acct

    acct.add_alert("HP Info Center LaunchApp called to run: %s %s" % (prog, args, ))
	
def SetRegValue(key, section, keyname, value):
    global acct

    acct.add_alert("HP Info Center SetRegValue: %s/%s/%s set to %s" % (str(key), str(section), str(keyname), str(value), ))

def GetRegValue(key, section, keyname):
    global acct

    acct.add_alert("HP Info Center GetRegValue, reading: %s/%s/%s" % (key, section, keyname, ))

def EvaluateRules():
    global acct

    acct.add_alert("HP Info Center EvaluateRules")

def SaveToFile(path):
    global acct

    acct.add_alert("HP Software Update SaveToFile(), writes to %s" % (path, ))
    acct.add_alert("HP Software Update SaveToFile(), writes to %s" % (path, ))

def ProcessRegistryData(parm):
    global acct

    acct.add_alert("HP Info Center ProcessRegistryData: %s " % (parm, ))


self.LaunchApp           = LaunchApp
self.SetRegValue         = SetRegValue
self.GetRegValue         = GetRegValue
self.EvaluateRules       = EvaluateRules
self.SaveToFile          = SaveToFile
self.ProcessRegistryData = ProcessRegistryData
