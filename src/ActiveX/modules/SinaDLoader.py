# Sina DLoader Class ActiveX Control 'DonwloadAndInstall' 
# Method Arbitrary File Download Vulnerability

import logging
log = logging.getLogger("Thug.ActiveX")

def DownloadAndInstall(self, url):
    log.warning('SinaDLoader Downloader ActiveX Vulnerability (URL: %s)' % (url, )) 

