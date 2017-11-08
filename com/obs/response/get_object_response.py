#!/usr/bin/python
# -*- coding:utf-8 -*-

from com.obs.models.base_model import BaseModel,BASESTRING
from com.obs.utils import common_util

class ResponseWrapper(object):
    def __init__(self, conn, result, connHolder):
        self.conn = conn
        self.result = result
        self.connHolder = connHolder

    def __getattr__(self, name):
        return getattr(self.result, name) if self.result else None

    def close(self):
        if self.conn:
            common_util.doClose(self.result, self.conn, self.connHolder)

class ObjectStream(BaseModel):

    allowedAttr = {'response': ResponseWrapper, 'buffer': object, 'size': int, 'url' : BASESTRING, 'deleteMarker' : bool, 
                   'storageClass': BASESTRING, 'accessContorlAllowOrigin': BASESTRING,'accessContorlAllowHeaders':BASESTRING, 'accessContorlAllowMethods':BASESTRING,
                   'accessContorlExposeHeaders':BASESTRING, 'accessContorlMaxAge':int, 'contentLength': int, 'cacheControl' : BASESTRING, 'contentDisposition': BASESTRING,
                   'contentEncoding' : BASESTRING, 'contentLanguage' : BASESTRING, 'contentType' : BASESTRING, 'expires': BASESTRING, 'websiteRedirectLocation': BASESTRING,
                   'lastModified': BASESTRING, 'etag': BASESTRING, 'versionId':BASESTRING, 'restore': BASESTRING, 'expiration': BASESTRING, 'sseKms': BASESTRING,'sseKmsKey':BASESTRING, 'sseC':BASESTRING, 'sseCKeyMd5':BASESTRING}