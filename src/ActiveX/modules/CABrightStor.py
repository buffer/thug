# CA BrightStor
# CVE-NOMATCH

def AddColumn(arg0,arg1):
	if len(arg0)>100:
		add_alert('CA BrightStor overflow in AddColumn()')

self.AddColumn=AddColumn
