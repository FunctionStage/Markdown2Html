#!/usr/bin/python
# -*- coding:utf-8 -*-
from com.obs.models.base_model import BaseModel

class Lifecycle(BaseModel):

    allowedAttr = {'rule': list}

    def __init__(self, rule=None):
        self.rule = rule