#!/usr/bin/python
# -*- coding:utf-8 -*-

from com.obs.models.base_model import BaseModel,BASESTRING

class UploadPartResponse(BaseModel):
    
    allowedAttr = {'etag': BASESTRING, 'sseKms': BASESTRING,'sseKmsKey':BASESTRING, 'sseC':BASESTRING, 'sseCKeyMd5':BASESTRING}