#!/usr/bin/python  
# -*- coding:utf-8 -*- 

import hashlib
import hmac
import binascii
from com.obs.utils import common_util
from com.obs.log.Log import *
from com.obs.models.base_model import IS_PYTHON2

class V2Authentication(object):

    def __init__(self, ak, sk, path_style):
        self.ak = ak
        self.sk = sk
        self.path_style = path_style


    def v2Auth(self, method, bucket, object, path_args, headers, expires=None):
        return 'AWS ' + self.ak + ':' + self.getSignature(method, bucket, object, path_args, headers, expires)

    def getSignature(self, method, bucket, object, path_args, headers, expires=None):
        canonical_string = self.__make_canonicalstring(method, bucket, object, path_args, headers, expires)
        LOG(DEBUG, 'v2 canonical_string: %s' % canonical_string)
        if IS_PYTHON2:
            hashed = hmac.new(self.sk, canonical_string, hashlib.sha1)  
            encode_canonical = binascii.b2a_base64(hashed.digest())[:-1]  
        else:
            hashed = hmac.new(self.sk.encode('UTF-8'), canonical_string.encode('UTF-8'), hashlib.sha1)  
            encode_canonical = binascii.b2a_base64(hashed.digest())[:-1].decode('UTF-8')  
        return encode_canonical

    def __make_canonicalstring(self, method, bucket_name, key, path_args, headers, expires=None):

        str_list = []
        str_list.append(method + '\n')

        interesting_headers = {}  
        content_list = ['content-type', 'content-md5', 'date']
        if isinstance(headers, dict):
            for hash_key in headers.keys():
                lk = hash_key.lower()  

                if lk in content_list or lk.startswith(common_util.AMAZON_HEADER_PREFIX):
                    s = headers.get(hash_key)  
                    interesting_headers[lk] = ''.join(s)

        keylist = interesting_headers.keys()

        if common_util.ALTERNATIVE_DATE_HEADER in keylist:
            interesting_headers.setdefault('date', '')

        if expires:
            interesting_headers['date'] = expires

        if not 'content-type' in keylist:
            interesting_headers['content-type'] = ''

        if not 'content-md5' in keylist:
            interesting_headers['content-md5'] = ''

        keylist = sorted(interesting_headers.keys())


        for k in keylist:
            header_key = str(k)
            if header_key.startswith(common_util.AMAZON_HEADER_PREFIX):
                str_list.append(header_key + ':' + interesting_headers[header_key])
            else:
                str_list.append(interesting_headers[header_key])
            str_list.append('\n')

        URI = ''
        if bucket_name is not None and bucket_name != '':
            URI += '/'
            URI += bucket_name
            if not self.path_style:
                URI += '/'

        if key is not None:
            if not URI.endswith('/'):
                URI += '/'
            URI += common_util.encode_object_key(key)

        str_list.append(URI) if URI else str_list.append('/')

        if path_args:
            e1 = '?'
            e2 = '&'
            for path_key, path_value in path_args.items():
                flag = True
                if path_key.lower() not in common_util.ALLOWED_RESOURCE_PARAMTER_NAMES:
                    flag = False
                if flag:
                    path_key = common_util.encode_item(common_util.toString(path_key), ' ,:?&%')
                    if path_value is None:
                        e1 += path_key + '&'
                        continue
                    e2 += path_key + '=' + common_util.encode_item(common_util.toString(path_value), ' ,:?&%') + '&'
            e = (e1 + e2).replace('&&', '&').replace('?&', '?')[:-1]
            str_list.append(e)
        return ''.join(str_list)  