# Microsoft MDAC RDS.Dataspace ActiveX
# CVE-2006-0003

acct = ActiveXAcct[self]

def createobject(*args):
    global acct

	acct.add_alert("Microsoft MDAC RDS.Dataspace ActiveX attack in createobject function");

self.createobject = createobject;
