
def GetVariable(arg):
	if arg == "$version":
		add_alert("GetVariable($version)")
		return "WIN 9,0,64,0"

self.GetVariable = GetVariable
