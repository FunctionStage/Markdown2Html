#!/usr/bin/python
# -*- coding:utf-8 -*-

import hashlib
import hmac
from com.obs.utils import common_util
from com.obs.models.base_model import IS_PYTHON2
from com.obs.log.Log import *


class V4Authentication(object):
    CONTENT_SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    def __init__(self, ak, sk, region, shortDate, longDate, path_style):
        self.ak = ak
        self.sk = sk
        self.region = region
        self.shortDate = shortDate
        self.longDate = longDate
        self.path_style = path_style
    
    def v4Auth(self, method, bucket, object, args_path, headers):
        args_path = args_path if isinstance(args_path, dict) else {}
        headers = headers if isinstance(headers, dict) else {}
        headers['x-amz-content-sha256'] = self.CONTENT_SHA256

        # date = headers['Date'] if 'Date' in headers else headers['date']
        # date = datetime.strptime(date, common_util.GMT_DATE_FORMAT)
        # self.shortDate = date.strftime(common_util.SHORT_DATE_FORMAT)
        # self.longDate = date.strftime(common_util.LONG_DATE_FORMAT)
        credenttial = self.getCredenttial()
        signedHeaders = self.getSignedHeaders(headers)
        signature = self.getSignature(method, bucket, object, args_path, headers)
        auth = 'AWS4-HMAC-SHA256 ' + 'Credential=' + credenttial + ',' + 'SignedHeaders=' + signedHeaders + ',' + 'Signature=' + signature
        return auth
    
    def getCredenttial(self):
        credenttial = self.ak + '/' + self.shortDate + '/' + self.region + '/'+'s3' + '/' + 'aws4_request'
        return credenttial
    
    def getScope(self):
        scope = self.shortDate + '/' + self.region + '/' + 's3' + '/' + 'aws4_request'
        return scope
    
    def getSignedHeaders(self,headers):
        headMap = self.setMapKeyLower(headers)
        headList = sorted(headMap.items(),key = lambda d:d[0])
        signedHeaders = ''
        i = 0
        for val in headList:
            if i != 0:
                signedHeaders += ';'
            signedHeaders +=  val[0]
            i = 1
        return signedHeaders
 
    def getSignature(self,method, bucket, object, args_path, headers, payload=None):
        outPut = 'AWS4-HMAC-SHA256' + '\n'
        outPut += self.longDate + '\n'
        outPut += self.getScope() + '\n'
        cannonicalRequest = self.getCanonicalRequest(method, bucket, object, args_path, headers, payload)
        LOG(DEBUG, 'v4 cannonicalRequest: %s' % cannonicalRequest)
        if IS_PYTHON2:
            stringToSign = outPut + self.__shaCannonicalRequest_python2(cannonicalRequest)
            signingKey = self.getSigningKey_python2()
        else:
            stringToSign = outPut + self.__shaCannonicalRequest_python3(cannonicalRequest)
            stringToSign = stringToSign.encode('UTF-8')
            signingKey = self.getSigningKey_python3()

        return self.hmacSha256(signingKey, stringToSign)

    def hmacSha256(self, signingKey, stringToSign):
        return hmac.new(signingKey, stringToSign, hashlib.sha256).hexdigest()

    def getSigningKey_python2(self):
        key = 'AWS4' + self.sk
        dateKey = hmac.new(key, self.shortDate, hashlib.sha256).digest()
        dateRegionKey = hmac.new(dateKey, self.region, hashlib.sha256).digest()
        dateRegionServiceKey = hmac.new(dateRegionKey, 's3', hashlib.sha256).digest()
        signingKey = hmac.new(dateRegionServiceKey, 'aws4_request', hashlib.sha256).digest()
        return signingKey

    def getSigningKey_python3(self):
        key = 'AWS4' + self.sk
        dateKey = hmac.new(key.encode('UTF-8'), self.shortDate.encode('UTF-8'), hashlib.sha256).digest()
        dateRegionKey = hmac.new(dateKey, self.region.encode('UTF-8'), hashlib.sha256).digest()
        dateRegionServiceKey = hmac.new(dateRegionKey, 's3'.encode('UTF-8'), hashlib.sha256).digest()
        signingKey = hmac.new(dateRegionServiceKey, 'aws4_request'.encode('UTF-8'), hashlib.sha256).digest()
        return signingKey
    
    def getCanonicalRequest(self,method,bucket,object,args_path,headers, payload=None):
        outPut = method + '\n'
        outPut += self.getCanonicalURI(bucket, object) + '\n'
        outPut += self.getCanonicalQueryString(args_path) + '\n' 
        outPut += self.getCanonicalHeaders(headers) + '\n'
        outPut += self.getSignedHeaders(headers) + '\n'
        outPut += (self.getHashedPayload() if payload is None else payload)
        return outPut


    def __shaCannonicalRequest_python2(self,cannonicalRequest):
        return hashlib.sha256(cannonicalRequest).hexdigest()

    def __shaCannonicalRequest_python3(self,cannonicalRequest):
        return hashlib.sha256(cannonicalRequest.encode('UTF-8')).hexdigest()

    def getCanonicalURI(self,bucket=None,object=None):
        URI = ''
        if self.path_style and bucket is not None and bucket != '':
            URI += '/' + bucket
        if object is not None:
            URI += '/' + object
        if not URI:
            URI = '/'
        return common_util.encode_object_key(URI)

    def getCanonicalQueryString(self,args_path):
        canonMap = {}
        for key,value in args_path.items():
            canonMap[key] = value
        cannoList = sorted(canonMap.items(),key = lambda d:d[0])
        queryStr = ''
        i = 0
        for val in cannoList:
            if i != 0:
                queryStr += '&'
            queryStr += '%s=%s'%(common_util.encode_item(val[0],' ,:?&%'), common_util.encode_item(val[1], ' ,:?&%')) #v4签名value必须转移'/'
            i = 1
        return queryStr

    def getCanonicalHeaders(self,headers):
        headMap = self.setMapKeyLower(headers)
        headList = sorted(headMap.items(),key = lambda d:d[0])
        canonicalHeaderStr = ''
        for val in headList:
            if isinstance(val[1], list):
                tlist = sorted(val[1])
                for v in tlist:
                    canonicalHeaderStr += val[0] + ':' + v + '\n'
            else:
                canonicalHeaderStr += val[0] + ':' + str(val[1]) + '\n'
        return canonicalHeaderStr

    def getHashedPayload(self):
        return self.CONTENT_SHA256
    
    def setMapKeyLower(self,inputMap):
        outputMap = {}
        for key in inputMap.keys():
            outputMap[key.lower()] = inputMap[key]
        return outputMap
    
        