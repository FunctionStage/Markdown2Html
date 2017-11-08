#!/usr/bin/python
# -*- coding:utf-8 -*-

from com.obs.models.base_model import BaseModel,BASESTRING

class PutContentResponse(BaseModel):
    
    allowedAttr = {'storageClass': BASESTRING, 'etag': BASESTRING, 'versionId':BASESTRING, 'sseKms': BASESTRING,'sseKmsKey':BASESTRING, 'sseC':BASESTRING, 'sseCKeyMd5':BASESTRING}