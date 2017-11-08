#!/usr/bin/python
# -*- coding:utf-8 -*-

from com.obs.models.base_model import BaseModel,BASESTRING

class DeleteObjectsRequest(BaseModel):

    allowedAttr = {'quiet': bool, 'objects': list}

    def __init__(self, quiet=None, objects=None):
        self.quiet = quiet
        self.objects = objects


    def add_object(self, object):
        if self.objects is None:
            self.objects = []
        if isinstance(object, Object):
            self.objects.append(object)

DeleteObjectsRequset = DeleteObjectsRequest

class Object(BaseModel):
    allowedAttr = {'key' : BASESTRING, 'versionId' : BASESTRING}

    def __init__(self, key=None, versionId=None):
        self.key = key
        self.versionId = versionId
