// Redkit Exploit Kit (rule #1)
rule Redkit_1 : Landing_page Exploit_Kit
{
  meta:
    author = "MalwareSigs"
  strings:
    $url = /\/[a-z]{4}\.html?(\?[hij]=\d{7})?$/ nocase
  condition:
    $url
}


// Redkit Exploit Kit (rule #2)
rule Redkit_2 : Java_exploit Exploit_Kit
{
  meta:
    author = "MalwareSigs"
  strings:
    $url = /\/[a-zA-Z0-9]{3}\.jar$/ nocase
  condition:
    $url
}


// Redkit Exploit Kit (rule #3)
rule Redkit_3 : EXE Exploit_Kit
{
  meta:
    author = "MalwareSigs"
  strings:
    $url = /\/[a-zA-Z0-9-.]+\/[0-9]{2}\.html$/ nocase
  condition:
    $url
}


// Redkit Exploit Kit (rule #4)
rule Redkit_4 : EXE Exploit_Kit
{
  meta:
    author = "https://twitter.com/malc0de"
  strings:
    $url = /\/\d{2}\.html\s/
  condition:
    $url
}
