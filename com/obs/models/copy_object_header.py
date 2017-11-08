#!/usr/bin/python
# -*- coding:utf-8 -*-

from com.obs.models.base_model import BaseModel,BASESTRING
from com.obs.models.date_time import DateTime
from com.obs.models.server_side_encryption import SseHeader

class CopyObjectHeader(BaseModel):
    allowedAttr = {'acl': BASESTRING, 'directive': BASESTRING, 'if_match': BASESTRING,
                   'if_none_match': BASESTRING, 'if_modified_since': [BASESTRING,DateTime], 'if_unmodified_since': [BASESTRING,DateTime], 'location': BASESTRING,
                   'destSseHeader': SseHeader, 'sourceSseHeader': SseHeader, 'cacheControl' : BASESTRING, 'contentDisposition': BASESTRING,
                   'contentEncoding' : BASESTRING, 'contentLanguage' : BASESTRING, 'contentType' : BASESTRING, 'expires': BASESTRING}


    def __init__(self, acl=None, directive=None, if_match=None, if_none_match=None, if_modified_since=None, if_unmodified_since=None, location=None,destSseHeader=None, sourceSseHeader=None):
        self.acl = acl
        self.directive = directive
        self.if_match = if_match
        self.if_none_match = if_none_match
        self.if_modified_since = if_modified_since
        self.if_unmodified_since = if_unmodified_since
        self.location = location
        self.destSseHeader = destSseHeader
        self.sourceSseHeader = sourceSseHeader