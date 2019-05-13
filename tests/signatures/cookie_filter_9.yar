rule cookie_filter_9
{
  strings:
    $cookie = "foobar="
  condition:
    all of them
}
