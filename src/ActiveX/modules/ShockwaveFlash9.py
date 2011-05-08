
def GetVariable(arg):
	if arg == "$version":
		print "GetVariable($version)"
		return "WIN 9,0,64,0"

self.GetVariable = GetVariable
