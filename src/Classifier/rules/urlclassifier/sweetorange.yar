// Sweet Orange Exploit Kit (rule #1)
rule SweetOrange_1 : PDF_or_JAR Exploit_Kit
{
  meta:
    author = "MalwareSigs"
  strings:
    $url = /\/[a-zA-Z]{5,10}$/ nocase
  condition:
    $url
}


// Sweet Orange Exploit Kit (rule #2)
rule SweetOrange_2 : Landing_or_Executable Exploit_Kit
{
  meta:
    author = "MalwareSigs"
  strings:
    $url = /\/[a-z]+\?\.php\?([a-z]+\?=[0-9]{1,3}&){3,}[a-z]+\?=[0-9]{1,3}$/ nocase
  condition:
    $url
}


// Sweet Orange Exploit Kit (rule #3)
rule SweetOrange_3 : Entry Exploit_Kit
{
  meta:
    author = "https://twitter.com/malc0de"
  strings:
    $a = "archive="
    $b = "sdj1"
  condition:
    $a and $b
}


// Sweet Orange Exploit Kit (rule #2)
rule SweetOrange_4 : JAR Exploit_Kit
{
  meta:
    author = "https://twitter.com/malc0de"
  strings:
    $a = /\/(mcINkf|YZjcS|tUaZFs)/
  condition:
    $a
}
