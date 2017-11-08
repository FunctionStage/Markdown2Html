#!/usr/bin/python
# -*- coding:utf-8 -*-

from com.obs.models.base_model import BaseModel,BASESTRING
from com.obs.models.grantee import Grantee


class Permission(object):
    READ = 'READ'
    WRITE = 'WRITE'
    READ_ACP = 'READ_ACP'
    WRITE_ACP = 'WRITE_ACP'
    FULL_CONTROL = 'FULL_CONTROL'

class Grant(BaseModel):
    
    allowedAttr = {'grantee': Grantee, 'permission': BASESTRING}
        

    def __init__(self, grantee = None, permission = None):
        self.grantee = grantee
        self.permission = permission
        


