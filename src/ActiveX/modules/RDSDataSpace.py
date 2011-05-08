# Microsoft MDAC RDS.Dataspace ActiveX
# CVE-2006-0003

def createobject(*args):
	add_alert("Microsoft MDAC RDS.Dataspace ActiveX attack in createobject function");

self.createobject=createobject;
