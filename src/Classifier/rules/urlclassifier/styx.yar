rule Styx_1 : Exploit_Kit
{
	 meta:
		author = "MalwareSigs"
	strings:
		$url = /\/[a-zA-Z0-9]{150,}/ nocase
	condition:
    	$url
}


rule Styx_2 : PluginDetect Exploit_Kit
{
     meta:
        author = "MalwareSigs"
    strings:
        $url = /\/[a-zA-Z0-9]{40,}\/pdfx.html/ nocase
    condition:
        $url
}


rule Styx_3 : JAR Exploit_Kit
{
     meta:
        author = "MalwareSigs"
    strings:
        $url = /\/[a-zA-Z0-9]{40,}\/[a-zA-Z0-9]{4,10}.jar/ nocase
    condition:
        $url
}


rule Styx_4 : PDF Exploit_Kit
{
     meta:
        author = "MalwareSigs"
    strings:
        $url = /\/[a-zA-Z0-9]{40,}\/[a-zA-Z0-9]{4,10}.pdf/ nocase
    condition:
        $url
}


rule Styx_5 : EOT Exploit_Kit
{
     meta:
        author = "MalwareSigs"
    strings:
        $url = /\/[a-zA-Z0-9]{40,}\/[a-zA-Z0-9]{4,10}.eot/ nocase
    condition:
        $url
}

rule Styx_6 : EXE Exploit_Kit
{
	meta:
		author = "Angelo Dell'Aera"
	strings:
		$url = /\/[a-zA-Z0-9]{40,}\/[a-zA-Z0-9]{4,10}.exe/ nocase
	condition:
		$url
}

rule Styx_7 : EXE Exploit_Kit
{
     meta:
        author = "MalwareSigs"
    strings:
        $url = /\/[a-zA-Z0-9]{150,}\/[a-zA-Z0-9]+.exe\?[a-zA-Z0-9=]+&h=[0-9]+$/ nocase
    condition: 
        $url
}  
