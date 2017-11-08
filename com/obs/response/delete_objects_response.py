#!/usr/bin/python
# -*- coding:utf-8 -*-

from com.obs.models.base_model import BaseModel,BASESTRING

class DeleteObjectsResponse(BaseModel):
    allowedAttr = {'deleted': list, 'error': list}


class ErrorResult(BaseModel):
    allowedAttr = {'key': BASESTRING, 'versionId' : BASESTRING, 'code': BASESTRING, 'message': BASESTRING}
        
class DeleteObjectResult(BaseModel):
    allowedAttr = {'key': BASESTRING, 'versionId' : BASESTRING, 'deleteMarker': bool, 'deleteMarkerVersionId': BASESTRING}
