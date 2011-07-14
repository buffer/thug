# Sina DLoader Class ActiveX Control 'DonwloadAndInstall' 
# Method Arbitrary File Download Vulnerability

acct = ActiveXAcct[self]

def DownloadAndInstall(url):
    global acct

    acct.add_alert('Downloader ActiveX Vulnerability')
    acct.add_alert('URL : ' + url)

self.DownloadAndInstall = DownloadAndInstall
