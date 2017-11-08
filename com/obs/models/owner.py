#!/usr/bin/python
# -*- coding:utf-8 -*-

from com.obs.models.base_model import BaseModel,BASESTRING
class Owner(BaseModel):
    
    allowedAttr = {'owner_id': BASESTRING, 'owner_name': BASESTRING}
        
    def __init__(self, owner_id = None, owner_name = None):
        self.owner_id = owner_id
        self.owner_name = owner_name