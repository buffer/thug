# Buffer overflow in PDF.PdfCtrl.1 for remote attackers to execute arbitrary code via the pdf.setview method
# CVE-1999-1576

acct = ActiveXAcct[self]

def setview(* args):
	acct.add_alert('Buffer overflow in PDF.PdfCtrl.1 by setview method')

self.setview = setview
