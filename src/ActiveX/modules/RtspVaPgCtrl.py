# RTSP MPEG4 SP Control 1.x
# CVE-NOMATCH

acct = ActiveXAcct[self]

def SetMP4Prefix(val):
    global acct

	if len(val) > 128:
		acct.add_alert('RTSP MPEG4 SP Control overflow in MP4Prefix property')

Attr2Fun['MP4Prefix'] = SetMP4Prefix
