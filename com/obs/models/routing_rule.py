#!/usr/bin/python
# -*- coding:utf-8 -*-


from com.obs.models.base_model import BaseModel

from com.obs.models.condition import Condition
from com.obs.models.redirect import Redirect

class RoutingRule(BaseModel):
    allowedAttr = {'condition': Condition, 'redirect': Redirect}

    def __init__(self, condition = None,redirect = None):
        self.condition = condition
        self.redirect = redirect