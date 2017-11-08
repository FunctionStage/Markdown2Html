#!/usr/bin/python
# -*- coding:utf-8 -*-

from com.obs.models.base_model import BaseModel,BASESTRING

class GetObjectRequest(BaseModel):
    allowedAttr = {'content_type': BASESTRING, 'content_language': BASESTRING,
                   'expires': BASESTRING, 'cache_control': BASESTRING, 'content_disposition': BASESTRING,
                   'content_encoding': BASESTRING, 'versionId': BASESTRING}

    def __init__(self, content_type=None, content_language=None, expires=None, cache_control=None, content_disposition=None, content_encoding=None, versionId=None):
        self.content_type = content_type
        self.content_language = content_language
        self.expires = expires
        self.cache_control = cache_control
        self.content_disposition = content_disposition
        self.content_encoding = content_encoding
        self.versionId = versionId