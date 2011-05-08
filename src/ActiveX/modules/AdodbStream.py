

def Open():
	print "Adodb.Stream Open"

def Write(s):
	print "Adodb.Stream Write"
	print s

def SaveToFile(filename, opt):
	print "Adodb.Stream SaveToFile"
	print filename
	print opt

def Close():
	print "Adodb.Stream Close"


self.Open	= Open
self.Write	= Write
self.SaveToFile = SaveToFile
self.Close	= Close
