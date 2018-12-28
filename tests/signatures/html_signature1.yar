rule test1
{
  strings:
    $html1 = "strVar"
    $html2 = "alert(myVar);"
  condition:
    all of them
}
