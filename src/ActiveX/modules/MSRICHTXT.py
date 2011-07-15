# Microsoft Rich Textbox Control 6.0 (SP6)
# CVE-NOMATCH

object = self
acct   = ActiveXAcct[self]

def SaveFile(path, arg):
    global object
    global acct
	
    acct.add_alert("Writing to file " + str(path) + " with contents: " + str(object.Text))

self.SaveFile = SaveFile
