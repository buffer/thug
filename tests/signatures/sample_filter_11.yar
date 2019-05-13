rule sample_filter_11
{
  strings:
    $code1 = "VirtualQuery"
  condition:
    all of them
}
