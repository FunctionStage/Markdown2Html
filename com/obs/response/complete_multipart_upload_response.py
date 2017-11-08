#!/usr/bin/python
# -*- coding:utf-8 -*-

from com.obs.models.base_model import BaseModel,BASESTRING

class CompleteMultipartUploadResponse(BaseModel):
    
    allowedAttr = {'location': BASESTRING, 'bucket': BASESTRING,
                   'key': BASESTRING, 'etag': BASESTRING, 'versionId' : BASESTRING, 'sseKms': BASESTRING,'sseKmsKey':BASESTRING, 'sseC':BASESTRING, 'sseCKeyMd5':BASESTRING}
    


