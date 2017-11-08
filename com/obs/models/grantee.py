#!/usr/bin/python
# -*- coding:utf-8 -*-

from com.obs.models.base_model import BaseModel,BASESTRING


class Group(object):
    ALL_USERE = 'http://acs.amazonaws.com/groups/global/AllUsers'
    AUTHENTICATED_USERS = 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'
    LOG_DELIVERY = 'http://acs.amazonaws.com/groups/s3/LogDelivery'

class Grantee(BaseModel):
    
    allowedAttr = {'grantee_id': BASESTRING, 'grantee_name': BASESTRING, 'group': BASESTRING}
 

    def __init__(self, grantee_id = None, grantee_name = None, group = None):
        self.grantee_id = grantee_id
        self.grantee_name = grantee_name
        self.group = group


     
    
    
    
    