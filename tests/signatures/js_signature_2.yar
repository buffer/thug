rule js_signature_2
{
  strings:
    $js1 = "document.createProcessingInstruction(document, 'foo')"
    $js2 = "alert(s.nodeValue)"
  condition:
    all of them
}
