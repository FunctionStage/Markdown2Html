#!/usr/bin/python
# -*- coding:utf-8 -*-

from com.obs.models.base_model import BaseModel,BASESTRING
class CopyPartResponse(BaseModel):
    allowedAttr = {'lastModified': BASESTRING, 'etag': BASESTRING, 'modifiedDate': BASESTRING,'etagValue': BASESTRING, 'sseKms': BASESTRING,'sseKmsKey':BASESTRING, 'sseC':BASESTRING, 'sseCKeyMd5':BASESTRING}

