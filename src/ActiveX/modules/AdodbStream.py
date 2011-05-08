

def Open():
	add_alert("Adodb.Stream Open")

def Write(s):
	add_alert("Adodb.Stream Write"
	add_alert(s)

def SaveToFile(filename, opt):
	add_alert("Adodb.Stream SaveToFile")
	add_alert(filename)
	add_alert(opt)

def Close():
	add_alert("Adodb.Stream Close")


self.Open	    = Open
self.Write	    = Write
self.SaveToFile = SaveToFile
self.Close	    = Close
