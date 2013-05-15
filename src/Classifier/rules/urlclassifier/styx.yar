// Styx Exploit Kit (rule #1)
rule Styx_1 : Exploit_Kit
{
	 meta:
		author = "MalwareSigs"
	strings:
		$url = /\/[a-zA-Z0-9]{150,}/ nocase
	condition:
    	$url
}


// Styx Exploit Kit (rule #2)
rule Styx_2 : PluginDetect Exploit_Kit
{
     meta:
        author = "MalwareSigs"
    strings:
        $url = /\/[a-zA-Z0-9]{40,}\/pdfx.html/ nocase
    condition:
        $url
}


// Styx Exploit Kit (rule #3)
rule Styx_3 : JAR Exploit_Kit
{
     meta:
        author = "MalwareSigs"
    strings:
        $url = /\/[a-zA-Z0-9]{40,}\/[a-zA-Z0-9]{4,10}.jar/ nocase
    condition:
        $url
}


// Styx Exploit Kit (rule #4)
rule Styx_4 : PDF Exploit_Kit
{
     meta:
        author = "MalwareSigs"
    strings:
        $url = /\/[a-zA-Z0-9]{40,}\/[a-zA-Z0-9]{4,10}.pdf/ nocase
    condition:
        $url
}


// Styx Exploit Kit (rule #5)
rule Styx_5 : EOT Exploit_Kit
{
     meta:
        author = "MalwareSigs"
    strings:
        $url = /\/[a-zA-Z0-9]{40,}\/[a-zA-Z0-9]{4,10}.eot/ nocase
    condition:
        $url
}


// Styx Exploit Kit (rule #6)
rule Styx_6 : EXE Exploit_Kit
{
	meta:
		author = "Angelo Dell'Aera"
	strings:
		$url = /\/[a-zA-Z0-9]{40,}\/[a-zA-Z0-9]{4,10}.exe/ nocase
	condition:
		$url
}


// Styx Exploit Kit (rule #7)
rule Styx_7 : EXE Exploit_Kit
{
     meta:
        author = "MalwareSigs"
    strings:
        $url = /\/[a-zA-Z0-9]{150,}\/[a-zA-Z0-9]+.exe\?[a-zA-Z0-9=]+&h=[0-9]+$/ nocase
    condition: 
        $url
}  


// Styx Exploit Kit (rule #8)
rule Styx_8 : EXE Exploit_Kit
{
	meta:
		author = "https://twitter.com/malc0de"
	strings:
		$a = /\/[a-zA-Z0-9]{180,}\/\w+\.exe\?o\=\d+\&h\=\d+/
		$b = /\/[a-zA-Z0-9]{180,}\/getmyfile.exe\?o\=\d/
	condition:
		$a or $b
}
