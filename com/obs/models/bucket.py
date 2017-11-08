#!/usr/bin/python
# -*- coding:utf-8 -*-

from com.obs.models.base_model import BaseModel, BASESTRING

class Bucket(BaseModel):
    
    allowedAttr = {'name': BASESTRING, 'create_date': BASESTRING}

