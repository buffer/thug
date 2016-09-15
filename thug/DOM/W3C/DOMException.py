#!/usr/bin/env python

from thug.DOM.JSClass import JSClass

class DOMException(RuntimeError, JSClass):
    def __init__(self, code):
        self.code = code

    # ExceptionCode
    INDEX_SIZE_ERR                 = 1  # If index or size is negative, or greater than the allowed value
    DOMSTRING_SIZE_ERR             = 2  # If the specified range of text does not fit into a DOMString
    HIERARCHY_REQUEST_ERR          = 3  # If any node is inserted somewhere it doesn't belong
    WRONG_DOCUMENT_ERR             = 4  # If a node is used in a different document than the one that created it (that doesn't support it)
    INVALID_CHARACTER_ERR          = 5  # If an invalid or illegal character is specified, such as in a name. 
    NO_DATA_ALLOWED_ERR            = 6  # If data is specified for a node which does not support data
    NO_MODIFICATION_ALLOWED_ERR    = 7  # If an attempt is made to modify an object where modifications are not allowed
    NOT_FOUND_ERR                  = 8  # If an attempt is made to reference a node in a context where it does not exist
    NOT_SUPPORTED_ERR              = 9  # If the implementation does not support the type of object requested
    INUSE_ATTRIBUTE_ERR            = 10 # If an attempt is made to add an attribute that is already in use elsewhere    

    # Introduced in Level 2
    INVALID_STATE_ERR              = 11 # If an attempt is made to use an object that is not, or is no longer, usable
    SYNTAX_ERR                     = 12 # If an invalid or illegal string is specified
    INVALID_MODIFICATION_ERR       = 13 # If an attempt is made to modify the type of the underlying object
    NAMESPACE_ERR                  = 14 # If an attempt is made to create or change an object in a way which is incorrect with regards to namespaces
    INVALID_ACCESS_ERR             = 15 # If a parameter or an operation is not supported by the underlying object

