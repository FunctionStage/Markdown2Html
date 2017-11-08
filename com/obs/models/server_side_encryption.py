#!/usr/bin/python  
# -*- coding:utf-8 -*- 

from com.obs.models.base_model import BaseModel,BASESTRING


class SseHeader(BaseModel):
    allowedAttr = {'encryption': BASESTRING, 'key': BASESTRING}


class SseCHeader(SseHeader):
    @staticmethod
    def getInstance(key,encryption='AES256'):
        return SseCHeader(encryption=encryption, key=key)

class SseKmsHeader(SseHeader):
    @staticmethod
    def getInstance(key=None,encryption='aws:kms'):
        return SseKmsHeader(encryption=encryption, key=key)

