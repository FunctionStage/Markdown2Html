#!/usr/bin/python
# -*- coding:utf-8 -*-

from com.obs.models.base_model import BaseModel,BASESTRING

class CopyObjectResponse(BaseModel):
    allowedAttr = {'lastModified': BASESTRING, 'etag': BASESTRING, 'copySourceVersionId' : BASESTRING, 'versionId' : BASESTRING,
                  'sseKms': BASESTRING,'sseKmsKey':BASESTRING, 'sseC':BASESTRING, 'sseCKeyMd5':BASESTRING}


