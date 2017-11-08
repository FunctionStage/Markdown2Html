#!/usr/bin/python
# -*- coding:utf-8 -*-

from com.obs.models.base_model import BaseModel,BASESTRING

from com.obs.models.date_time import DateTime
from com.obs.models.server_side_encryption import SseHeader

class GetObjectHeader(BaseModel):
    allowedAttr = {'range': BASESTRING, 'if_modified_since': [BASESTRING,DateTime],
                   'if_unmodified_since': [BASESTRING,DateTime], 'if_match': BASESTRING, 'if_none_match': BASESTRING,
                   'origin': BASESTRING, 'requestHeaders': BASESTRING,'sseHeader': SseHeader}


    def __init__(self, range=None, if_modified_since=None, if_unmodified_since=None, if_match=None, if_none_match=None, origin=None,
                 requestHeaders=None, sseHeader=None):
        self.range = range
        self.if_modified_since = if_modified_since
        self.if_unmodified_since = if_unmodified_since
        self.if_match = if_match
        self.if_none_match = if_none_match
        self.origin = origin
        self.requestHeaders = requestHeaders
        self.sseHeader = sseHeader