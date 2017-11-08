#!/usr/bin/python
# -*- coding:utf-8 -*-

from com.obs.models.base_model import BaseModel

class GetBucketQuotaResponse(BaseModel):
    allowedAttr = {'quota': int}
    

