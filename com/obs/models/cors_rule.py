#!/usr/bin/python
# -*- coding:utf-8 -*-

from com.obs.models.base_model import BaseModel,BASESTRING


class CorsRule(BaseModel):
    allowedAttr = {'id': BASESTRING, 'allowedMethod': list, 'allowedOrigin': list,
                   'allowedHeader': list, 'maxAgeSecond': int, 'exposeHeader': list}

    def __init__(self,id=None,allowedMethod=None,allowedOrigin=None,allowedHeader=None,maxAgeSecond=None,exposeHeader=None):
        self.id = id
        self.allowedMethod = allowedMethod
        self.allowedOrigin = allowedOrigin
        self.allowedHeader = allowedHeader
        self.maxAgeSecond = maxAgeSecond
        self.exposeHeader = exposeHeader