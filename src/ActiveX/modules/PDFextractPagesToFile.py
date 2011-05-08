# VSPDFEditorX.VSPDFEdit ActiveX allows remote attackers to create or overwrite arbitrary files via the first argument to  #the extractPagesToFile method
# CVE-2008-6496


def extractPagesToFile(arg0, *arg):
	add_alert('VSPDFEditorX.VSPDFEdit ActiveX is to create or overwrite file: ' + arg0)

self.extractPagesToFile=extractPagesToFile
