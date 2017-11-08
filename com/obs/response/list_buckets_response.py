#!/usr/bin/python
# -*- coding:utf-8 -*-

from com.obs.models.base_model import BaseModel
from com.obs.models.owner import Owner


class ListBucketsResponse(BaseModel):

    allowedAttr = {'buckets': list, 'owner': Owner}
            

 
    
    