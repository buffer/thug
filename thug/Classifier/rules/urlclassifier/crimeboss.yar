// Crimeboss Exploit Kit (rule #1)
rule Crimeboss_1 : Exploit_Kit
{	
  meta:
    author = "https://twitter.com/malc0de"
  strings:
    $url = /\.php\?x\=s\&\w+\=\d+\&no\=\d/ nocase
  condition:
    $url
}


// Crimeboss Exploit Kit (rule #2)
rule Crimeboss_2 : JAR Exploit_Kit
{
  meta:
    author = "https://twitter.com/malc0de"
  strings:
    $url = /\/[a-z0-9]{3,4}\.jar\?r\=\d{6}\s/ nocase
  condition:
    $url
}


// Crimeboss Exploit Kit (rule #3)
rule Crimeboss_3 : Exploit_Kit
{
  meta:
    author = "MalwareSigs"
  strings:
    $url = /\/(\.php\?action=jv&h=|phedex\/|jex\/|cbx\/|pka[1-7]\.jar|xul1\.jar|javab\.jar\?r=|java7\.jar\?r=|amor1\.jar|jmx\.jar|jhan\.jar|m11\.jar|\/index\.php\?action=stats_|\/index\.php\?setup=d)/ nocase
  condition:
    $url
}
