rule html_filter_2
{
  strings:
    $html1 = "MATCH FILTER 2" nocase
  condition:
    all of them
}
