#!/usr/bin/python
# -*- coding:utf-8 -*-

from com.obs.models.base_model import BaseModel,BASESTRING

class ObjectVersionHead(BaseModel):

    allowedAttr = {'name': BASESTRING, 'prefix': BASESTRING, 'delimiter': BASESTRING,'keyMarker':BASESTRING, 'versionIdMarker':BASESTRING,
                   'nextKeyMarker':BASESTRING, 'nextVersionIdMarker':BASESTRING, 'maxKeys':int, 'isTruncated': bool}