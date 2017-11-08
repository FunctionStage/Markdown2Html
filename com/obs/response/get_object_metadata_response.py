#!/usr/bin/python
# -*- coding:utf-8 -*-

from com.obs.models.base_model import BaseModel,BASESTRING

class GetObjectMetadataResponse(BaseModel):
    
    allowedAttr = {'storageClass': BASESTRING, 'accessContorlAllowOrigin': BASESTRING,'accessContorlAllowHeaders':BASESTRING, 'accessContorlAllowMethods':BASESTRING,
                   'accessContorlExposeHeaders':BASESTRING, 'accessContorlMaxAge':int, 'contentLength': int, 'contentType': BASESTRING, 'websiteRedirectLocation': BASESTRING,
                   'lastModified': BASESTRING, 'etag': BASESTRING, 'versionId':BASESTRING, 'restore': BASESTRING, 'expiration': BASESTRING, 'sseKms': BASESTRING,'sseKmsKey':BASESTRING, 'sseC':BASESTRING, 'sseCKeyMd5':BASESTRING}