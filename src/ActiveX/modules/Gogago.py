# Gogago YouTube Video Converter Buffer Overflow
# HTB23012

acct = ActiveXAcct[self]

def Download(arg):
    global acct

    if len(arg) > 1024:
        acct.add_alert('Gogago YouTube Video Converter Buffer Overflow')

self.Download = Download
