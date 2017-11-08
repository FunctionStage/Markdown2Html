#!/usr/bin/python
# -*- coding:utf-8 -*-


from com.obs.models.base_model import BaseModel,BASESTRING

class RedirectAllRequestTo(BaseModel):

    allowedAttr = {'hostName': BASESTRING, 'protocol': BASESTRING}

    def __init__(self, hostName=None, protocol=None):
        self.hostName = hostName
        self.Protocol = protocol