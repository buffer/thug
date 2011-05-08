# Microsoft Rich Textbox Control 6.0 (SP6)
# CVE-NOMATCH

object = self

def SaveFile(path, arg):
	global object
	add_alert("Writing to file " + str(path) + " with contents: " + str(object.Text))

self.SaveFile = SaveFile
