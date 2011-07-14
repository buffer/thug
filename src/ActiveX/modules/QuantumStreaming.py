# Move Networks Quantum Streaming Player Control
# CVE-NOMATCH

acct = ActiveXAcct[self]

def UploadLogs(url, arg):
    global acct

	if len(url) > 20000:
		acct.add_alert('Quantum Streaming Player overflow in UploadLogs()')

self.UploadLogs = UploadLogs
