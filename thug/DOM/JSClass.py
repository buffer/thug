import os
import collections.abc


class JSClass:
    def __init__(self):
        self.__properties__ = {}
        self.__methods__ = {}
        self.__watchpoints__ = {}

    def __str__(self):
        return self.toString()

    def __getattr__(self, name):
        if name == 'constructor':
            return JSClassConstructor(self.__class__)

        if name == 'prototype':
            return JSClassPrototype(self.__class__)

        prop = self.__properties__.get(name, None)

        if prop and isinstance(prop[0], collections.abc.Callable):
            return prop[0]()

        method = self.__methods__.get(name, None)
        if method and isinstance(method, collections.abc.Callable):
            return method

        raise AttributeError(name)

    def __setattr__(self, name, value):
        prop = self.__properties__.get(name, None)

        if prop and isinstance(prop[1], collections.abc.Callable):
            return prop[1](value)

        return object.__setattr__(self, name, value)

    def toString(self):
        """Returns a string representation of an object"""
        return f"[object {self.__class__.__name__}]"

    def toLocaleString(self):
        """Returns a value as a string value appropriate to the host environment's current locale"""
        return self.toString()

    def valueOf(self):
        """Returns the primitive value of the specified object"""
        return self

    def hasOwnProperty(self, name):
        """Returns a Boolean value indicating whether an object has a property with the specified name"""
        return hasattr(self, name)

    def __defineGetter__(self, name, getter):
        """Binds an object's property to a function to be called when that property is looked up"""
        self.__properties__[name] = (getter, self.__lookupSetter__(name))

    def __lookupGetter__(self, name):
        """Return the function bound as a getter to the specified property"""
        return self.__properties__.get(name, (None, None))[0]

    def __defineSetter__(self, name, setter):
        """Binds an object's property to a function to be called when an attempt is made to set that property"""
        self.__properties__[name] = (self.__lookupGetter__(name), setter)

    def __lookupSetter__(self, name):
        """Return the function bound as a setter to the specified property"""
        return self.__properties__.get(name, (None, None))[1]

    def watch(self, prop, handler):
        """Watches for a property to be assigned a value and runs a function when that occurs"""
        self.__watchpoints__[prop] = handler

    def unwatch(self, prop):
        """Removes a watchpoint set with the watch method"""
        self.__watchpoints__.pop(prop, None)


class JSClassConstructor(JSClass):
    def __init__(self, cls):
        self.cls = cls

    @property
    def name(self):
        return self.cls.__name__

    def toString(self):
        return f"function {self.name}() {{{os.linesep}  [native code]{os.linesep}}}"

    def __call__(self, *args, **kwds):
        return self.cls(*args, **kwds)


class JSClassPrototype(JSClass):
    def __init__(self, cls):
        self.cls = cls

    @property
    def constructor(self):
        return JSClassConstructor(self.cls)

    @property
    def name(self):
        return self.cls.__name__
