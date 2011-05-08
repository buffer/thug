# PDFVIEW.PdfviewCtrl.1 ActiveX control allows remote attackers to execute arbitrary code via a long first argument to the OpenPDF method.

# CVE-2008-5492

def OpenPDF(arg0, *args):
	if len(arg0)>1000:
		add_alert('The OpenPDF method overflow in PDFVIEW.PdfviewCtrl.1 ActiveX control')

self.OpenPDF=OpenPDF
