#!/usr/bin/python
# -*- coding:utf-8 -*-


from com.obs.models.base_model import BaseModel,BASESTRING
class IndexDocument(BaseModel):

    allowedAttr = {'suffix': BASESTRING}

    def __init__(self, suffix=None):
        self.suffix = suffix