# DVRHOST Web CMS OCX 1.x
# CVE-NOMATCH

def TimeSpanFormat(arg0,arg1):
	if len(arg1)>512:
		add_alert('DVRHOST Web CMS OCX overflow in TimeSpanFormat()')

self.TimeSpanFormat=TimeSpanFormat
