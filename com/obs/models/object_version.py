#!/usr/bin/python
# -*- coding:utf-8 -*-

from com.obs.models.base_model import BaseModel,BASESTRING,LONG
from com.obs.models.owner import Owner

class ObjectVersion(BaseModel):

    allowedAttr = {'key': BASESTRING, 'versionId': BASESTRING, 'isLatest': bool, 'lastModified': BASESTRING,
                   'etag': BASESTRING, 'size': LONG, 'owner': Owner, 'storageClass': BASESTRING}