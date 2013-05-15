rule Traffic_Broker_1 : TDS
{
	meta:
		author = "https://twitter.com/malc0de"
    strings:
        $url = /rd.php\?http/ nocase
    condition:
        $url
}


rule Sutra_1 : TDS
{
	meta:
		author = "https://twitter.com/malc0de"
	strings:
		$url = /\/in.cgi\?\d/ nocase
	condition:
		$url
}
