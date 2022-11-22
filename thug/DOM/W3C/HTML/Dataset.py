#!/usr/bin/env python

import re

class Dataset:
    def __init__(self, attrs):
        self.__dict__['attrs'] = attrs

    def __getattr__(self, attr):
        data_attr = re.sub('([A-Z])', r'-\1', attr).lower()
        return self.__dict__['attrs'].get(f'data-{data_attr}', '')

    def __setattr__(self, attr, value):
        data_attr = re.sub('([A-Z])', r'-\1', attr).lower()
        self.__dict__['attrs'].__setitem__(f'data-{data_attr}', value)

    def __delattr__(self, attr):
        data_attr = re.sub('([A-Z])', r'-\1', attr).lower()
        self.__dict__['attrs'].__delitem__(f'data-{data_attr}')
