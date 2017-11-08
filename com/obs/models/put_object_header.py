#!/usr/bin/python
# -*- coding:utf-8 -*-

from com.obs.models.base_model import BaseModel,BASESTRING, LONG
from com.obs.models.server_side_encryption import SseHeader

class PutObjectHeader(BaseModel):
    allowedAttr = {'md5': BASESTRING, 'acl': BASESTRING, 'location': BASESTRING,
                   'contentType': BASESTRING, 'sseHeader': SseHeader, 'contentLength' : [int, LONG, BASESTRING]}

 
    def __init__(self, md5=None, acl=None, location=None, contentType=None, sseHeader=None, contentLength=None):
        self.md5 = md5
        self.acl = acl
        self.location = location
        self.contentType = contentType
        self.sseHeader = sseHeader
        self.contentLength = contentLength

