rule text_signature_5
{
  strings:
    $text1 = "This is a test"
  condition:
    all of them
}
