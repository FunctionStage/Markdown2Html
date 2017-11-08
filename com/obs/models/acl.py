#!/usr/bin/python
# -*- coding:utf-8 -*-

from com.obs.models.base_model import BaseModel
from com.obs.models.grant import Grant
from com.obs.models.owner import Owner

class ACL(BaseModel):

    allowedAttr = {'owner': Owner, 'grants': list}

    def __init__(self, owner=None, grants=None):
        self.owner = owner  
        self.grants = grants  
        
    def add_grant(self, grant):
        if self.grants is not None and isinstance(grant, Grant):
            self.grants.append(grant)




