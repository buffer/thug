rule html_signature_1
{
  meta:
    etags = "$html1"
    domain_whitelist = "github.com"
  strings:
    $html1 = "strVar"
    $html2 = "alert(myVar);"
  condition:
    all of them
}
