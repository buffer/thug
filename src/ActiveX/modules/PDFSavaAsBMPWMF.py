# PDF417 ActiveX control (MW6PDF417Lib.PDF417, MW6PDF417.dll) 3.0.0.1 allow remote attackers to overwrite arbitrary files #via a full pathname argument to the (1) SaveAsBMP and (2) SaveAsWMF methods.
# CVE-2008-4926

def SaveAsBMP(arg0):
	add_alert('Overwrite arbitrary files in MW6PDF417Lib.PDF417 SaveAsBMP() method')

def SaveAsWMF(arg0):
	add_alert('Overwrite arbitrary files in MW6PDF417Lib.PDF417 SaveAsWMF() method')


self.SaveAsBMP=SaveAsBMP
self.SaveAsWMF=SaveAsWMF

