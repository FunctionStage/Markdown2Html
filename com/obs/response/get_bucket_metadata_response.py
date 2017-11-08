#!/usr/bin/python
# -*- coding:utf-8 -*-

from com.obs.models.base_model import BaseModel,BASESTRING

class GetBucketMetadataResponse(BaseModel):
    
    allowedAttr = {'storageClass': BASESTRING, 'accessContorlAllowOrigin': BASESTRING,'accessContorlAllowHeaders':BASESTRING, 'accessContorlAllowMethods':BASESTRING,
                   'accessContorlExposeHeaders':BASESTRING, 'accessContorlMaxAge':int}