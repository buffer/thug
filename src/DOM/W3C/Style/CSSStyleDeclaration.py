#!/usr/bin/env python

class CSSStyleDeclaration(object):
    def __init__(self, style):
        #self.props = dict([prop.strip().split(': ') for prop in style.split(';') if prop])
        self.props = dict()

        for prop in [p for p in style.split(';') if p]:
            k, v = prop.strip().split(':')
            self.props[k.strip()] = v.strip()
         
        for k, v in self.props.items():
            if v and v[0] == v[-1] and v[0] in ['"', "'"]:
                self.props[k] = v[1:-1]

    @property
    def cssText(self):
        return '; '.join(["%s: %s" % (k, v) for k, v in self.props.items()])

    def getPropertyValue(self, name):
        return self.props.get(name, '')

    def removeProperty(self, name):
        v = self.props.get(name, '')

        if v:
            del self.props[name]

        return v

    @property
    def length(self):
        return len(self.props)

    def item(self, index):
        if type(index) == str:
            return self.props.get(index, '')

        if index < 0 or index >= len(self.props):
            return ''

        return self.props[self.props.keys()[index]]

    def __getattr__(self, name):
        if hasattr(object, name):
            return object.__getattribute__(self, name)
        else:
            return object.__getattribute__(self, 'props').get(name, '')

    def __setattr__(self, name, value):
        if name == 'props':
            object.__setattr__(self, name, value)
        else:
            object.__getattribute__(self, 'props')[name] = value
