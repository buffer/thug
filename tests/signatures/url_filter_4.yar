rule url_filter_4
{
  strings:
    $url1 = "www.google.com"
  condition:
    all of them
}
