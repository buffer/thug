# Move Networks Quantum Streaming Player Control
# CVE-NOMATCH

def UploadLogs(url, arg):
	if len(url)>20000:
		add_alert('Quantum Streaming Player overflow in UploadLogs()')

self.UploadLogs=UploadLogs
