#!/usr/bin/python  
# -*- coding:utf-8 -*- 

from com.obs.models.base_model import BaseModel,BASESTRING

class Tag(BaseModel):
    allowedAttr = {'key': BASESTRING, 'value': BASESTRING}
    
    def __init__(self, key=None, value=None):
        self.key = key
        self.value = value

class TagInfo(BaseModel):

    allowedAttr = {'tagSet': list}
    
    def __init__(self, tagSet=None):
        self.tagSet = tagSet
    
    def addTag(self, key, value):
        if self.tagSet is None:
            self.tagSet = []
        self.tagSet.append(Tag(key=key, value=value))
        return self







