# Insecure FtpDownloadFile method vulnerability in the PDFVIEWER.PDFViewerCtrl.1 ActiveX control (pdfviewer.ocx)
# CVE-2009-2169

acct = ActiveXAcct[self]

def FtpDownloadFile(arg0, arg1):
    global acct

    acct.add_alert('PDFVIEWER.PDFViewerCtrl.1 FtpDownloadFile method is to download ' + arg0)

self.FtpDownloadFile = FtpDownloadFile


