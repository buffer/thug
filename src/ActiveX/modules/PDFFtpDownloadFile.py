# Insecure FtpDownloadFile method vulnerability in the PDFVIEWER.PDFViewerCtrl.1 ActiveX control (pdfviewer.ocx)
# CVE-2009-2169

def FtpDownloadFile(arg0, arg1):
	add_alert('PDFVIEWER.PDFViewerCtrl.1 FtpDownloadFile method is to download '+ arg0)
self.FtpDownloadFile=FtpDownloadFile


