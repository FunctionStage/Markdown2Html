#!/usr/bin/python
# -*- coding:utf-8 -*-

from com.obs.models.base_model import BaseModel,LONG

class GetBucketStorageInfoResponse(BaseModel):
    allowedAttr = {'size': LONG, 'objectNumber': int}

