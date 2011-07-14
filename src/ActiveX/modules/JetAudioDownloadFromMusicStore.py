# jetAudio "DownloadFromMusicStore()" Arbitrary File Download Vulnerability
# CVE-2007-4983

acct = ActiveXAcct[self]

def DownloadFromMusicStore(url, dst, title, artist, album, genere, size, param1, param2):
    global acct

    acct.add_alert('Downloading ' + url + ' and saving locally as ' + dst)

self.DownloadFromMusicStore = DownloadFromMusicStore
