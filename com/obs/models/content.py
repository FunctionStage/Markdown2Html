#!/usr/bin/python
# -*- coding:utf-8 -*-

from com.obs.models.base_model import BaseModel,BASESTRING, LONG
from com.obs.models.owner import Owner
class Content(BaseModel):

    allowedAttr = {'key': BASESTRING, 'lastModified': BASESTRING, 'etag': BASESTRING,
                   'size': LONG, 'owner': Owner, 'storageClass': BASESTRING}
    def __str__(self):
        return self.key
    
    
    
    
    