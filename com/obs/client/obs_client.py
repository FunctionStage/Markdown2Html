#!/usr/bin/python  
# -*- coding:utf-8 -*- 

from com.obs.log.log_client import NoneLogClient, INFO, WARNING, ERROR, DEBUG, LogClient, LogConf
from com.obs.log.Log import LOG, LogInit
from com.obs.utils.request_format import RequestFormat
from com.obs.utils.request_format import PathFormat
from com.obs.utils import convert_util
from com.obs.utils import common_util
from com.obs.utils.v4_authentication import V4Authentication
from com.obs.utils.v2_authentication import V2Authentication
from com.obs.response.get_result import GetResult, RedirectException
from com.obs.models.restore import Restore
from com.obs.models.date_time import DateTime
from com.obs.models.server_side_encryption import SseCHeader,SseKmsHeader, SseHeader
from com.obs.models.base_model import IS_PYTHON2, IS_WINDOWS, BASESTRING
from com.obs.models.create_bucket_header import CreateBucketHeader
from com.obs.models.acl import ACL
from com.obs.models.logging import Logging
from com.obs.models.notification import Notification
from com.obs.models.list_multipart_uploads_request import ListMultipartUploadsRequest
from com.obs.models.options import Options
from com.obs.models.get_object_request import GetObjectRequest
from com.obs.models.get_object_header import GetObjectHeader
from com.obs.models.put_object_header import PutObjectHeader
from com.obs.models.copy_object_header import CopyObjectHeader
from com.obs.models.complete_multipart_upload_request import CompleteMultipartUploadRequest


import socket
import time
import functools
import threading
import os
import sys


if IS_PYTHON2:
    from urlparse import urlparse
    import httplib
    import imp
else:
    import http.client as httplib
    from urllib.parse import urlparse
    



def countTime(func):
    @functools.wraps(func)
    def wrapper(*args, **kw):
        start = time.time()
        try:
            ret = func(*args, **kw)
        except RedirectException as e:
            try:
                ret = func(*args, **kw)
            finally:
                GetResult.CONTEXT.location = None
        LOG(INFO, '%s cost %s ms' % (func.__name__ ,int((time.time() - start) * 1000)))
        return ret
    return wrapper



class ObsClient(object):

    DEFAULT_SECURE_PORT = 443
    DEFAULT_INSECURE_PORT = 80
    DEFAULT_HOST_NAME = 'obs.myhwclouds.com'

    def __init__(self, access_key_id, secret_access_key, is_secure=True, server=None, signature='v4', region='CHINA', path_style=False, ssl_verify=False,
                 port=None, max_retry_count=3, timeout=60, chunk_size=65536, long_conn_mode=False):
        self.access_key_id = common_util.safe_encode(access_key_id)
        self.secret_access_key = common_util.safe_encode(secret_access_key)
        self.is_secure = is_secure
        self.server = server if server is not None else self.DEFAULT_HOST_NAME
        self.server = common_util.safe_encode(server)
        self.signature = common_util.safe_encode(signature)
        self.region = region
        self.path_style = path_style
        self.ssl_verify = ssl_verify
        self.calling_format = RequestFormat.get_pathformat() if self.path_style else RequestFormat.get_subdomainformat()
        self.port = port if port is not None else self.DEFAULT_SECURE_PORT if is_secure else self.DEFAULT_INSECURE_PORT
        self.max_retry_count = max_retry_count
        self.timeout = timeout
        self.chunk_size = chunk_size
        self.log_client = NoneLogClient()
        self.context = None
        if self.is_secure:
            try:
                import ssl
                if hasattr(ssl, 'SSLContext'):
                    context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
                    context.options |= ssl.OP_NO_SSLv2
                    context.options |= ssl.OP_NO_SSLv3
                    if self.ssl_verify:
                        import _ssl
                        cafile = common_util.toString(self.ssl_verify)
                        context.options |= getattr(_ssl, "OP_NO_COMPRESSION", 0)
                        context.verify_mode = ssl.CERT_REQUIRED
                        if os.path.isfile(cafile):
                            context.load_verify_locations(cafile)
                    else:
                        context.verify_mode = ssl.CERT_NONE
                        
                    self.context = context
                    if hasattr(self.context, 'check_hostname'):
                        self.context.check_hostname = False
                else:
                    self.context = None
            except:
                import traceback
                print(traceback.format_exc())
        self.long_conn_mode = long_conn_mode
        self.connHolder = {'connSet' : set(), 'lock' : threading.Lock()} if self.long_conn_mode else None


    def initLog(self, log_config=LogConf(), log_name='OBS_LOGGER'):
        self.log_client = LogClient(log_config, 'OBS_LOGGER' if IS_WINDOWS else log_name, log_name)
        LogInit(log_config)

    def __assert_not_null(self, param, msg):
        param = common_util.safe_encode(param)
        if param is None or common_util.toString(param).strip() == '':
            raise Exception(msg)

    def __prepareParameterForSignedUrl(self, bucketName, specialParam, expires, headers, queryParams):
        if headers is None or not isinstance(headers, dict):
            headers = {}
        else:
            headers = headers.copy()

        if queryParams is None or not isinstance(queryParams, dict):
            queryParams = {}
        else:
            queryParams = queryParams.copy()

        if specialParam is not None:
            queryParams[specialParam] = None

        expires = 300 if expires is None else common_util.toInt(expires)

        calling_format = self.calling_format if common_util.valid_subdomain_bucketname(
            bucketName) else RequestFormat.get_pathformat()

        return headers, queryParams, expires, calling_format

    def createV2SignedUrl(self, method, bucketName=None, objectKey=None, specialParam=None, expires=300, headers=None, queryParams=None):

        headers, queryParams, expires, calling_format = self.__prepareParameterForSignedUrl(bucketName, specialParam, expires, headers, queryParams)

        expires += common_util.toInt(time.time())

        v2Auth = V2Authentication(self.access_key_id, self.secret_access_key, self.path_style)

        signature = v2Auth.getSignature(method, bucketName, objectKey, queryParams, headers, common_util.toString(expires))

        queryParams['Expires'] = expires
        queryParams['AWSAccessKeyId'] = self.access_key_id
        queryParams['Signature'] = signature

        return calling_format.get_full_url(self.is_secure, self.server, self.port, bucketName, objectKey, queryParams)

    def createV4SignedUrl(self, method, bucketName=None, objectKey=None, specialParam=None, expires=300, headers=None, queryParams=None):
        if IS_PYTHON2:
            imp.acquire_lock()
            try:
                from datetime import datetime
            finally:
                imp.release_lock()
        else:
            from datetime import datetime

        headers, queryParams, expires, calling_format = self.__prepareParameterForSignedUrl(bucketName, specialParam, expires, headers, queryParams)

        headers['host'] = calling_format.get_server(self.server, bucketName)

        date = headers['Date'] if 'Date' in headers else headers.get('date')
        date = datetime.strptime(date, common_util.GMT_DATE_FORMAT) if date else datetime.utcnow()
        shortDate = date.strftime(common_util.SHORT_DATE_FORMAT)
        longDate = date.strftime(common_util.LONG_DATE_FORMAT)
        v4Auth = V4Authentication(self.access_key_id, self.secret_access_key,  self.region, shortDate, longDate, self.path_style)

        queryParams['X-Amz-Algorithm'] = 'AWS4-HMAC-SHA256'
        queryParams['X-Amz-Credential'] = v4Auth.getCredenttial()
        queryParams['X-Amz-Date'] = longDate
        queryParams['X-Amz-Expires'] = expires
        queryParams['X-Amz-SignedHeaders'] = v4Auth.getSignedHeaders(headers)

        signature = v4Auth.getSignature(method, bucketName, objectKey, queryParams, headers, 'UNSIGNED-PAYLOAD')

        queryParams['X-Amz-Signature'] = signature

        result = {
            'signedUrl': calling_format.get_full_url(self.is_secure, self.server, self.port, bucketName, objectKey, queryParams),
            'actualSignedRequestHeaders': headers
        }
        from com.obs.models.base_model import BaseModel
        class CreateV4SignedUrlResponse(BaseModel):
            allowedAttr = {'signedUrl': BASESTRING, 'actualSignedRequestHeaders': dict}
        
        return CreateV4SignedUrlResponse(**result)

    def createV4PostSignature(self, bucketName=None, objectKey=None, expires=300, formParams=None):
        if IS_PYTHON2:
            imp.acquire_lock()
            try:
                from datetime import datetime,timedelta
            finally:
                imp.release_lock()
        else:
            from datetime import datetime, timedelta

        date = datetime.utcnow()
        shortDate = date.strftime(common_util.SHORT_DATE_FORMAT)
        longDate = date.strftime(common_util.LONG_DATE_FORMAT)

        credential = '%s/%s/%s/s3/aws4_request' % (self.access_key_id, shortDate, self.region)

        expires = 300 if expires is None else common_util.toInt(expires)
        expires = date + timedelta(seconds=expires)

        expires = expires.strftime(common_util.EXPIRATION_DATE_FORMAT)


        if formParams is None or not isinstance(formParams, dict):
            formParams = {}
        else:
            formParams = formParams.copy()

        formParams['X-Amz-Algorithm'] = 'AWS4-HMAC-SHA256'
        formParams['X-Amz-Date'] = longDate
        formParams['X-Amz-Credential'] = credential

        if bucketName:
            formParams['bucket'] = bucketName

        if objectKey:
            formParams['key'] = objectKey

        policy = ['{"expiration":"']
        policy.append(expires)
        policy.append('", "conditions":[')

        matchAnyBucket = True
        matchAnyKey = True

        conditionAllowKeys = ['acl', 'bucket', 'key', 'success_action_redirect', 'redirect', 'success_action_status']

        for key, value in formParams.items():
            if key:
                key = common_util.toString(key).lower()

                if key == 'bucket':
                    matchAnyBucket = False
                elif key == 'key':
                    matchAnyKey = False

                if key not in common_util.ALLOWED_REQUEST_HTTP_HEADER_METADATA_NAMES and not key.startswith(
                    common_util.AMAZON_HEADER_PREFIX) and key not in conditionAllowKeys:
                    key = common_util.METADATA_PREFIX + key

                policy.append('{"')
                policy.append(key)
                policy.append('":"')
                policy.append(common_util.toString(value) if value is not None else '')
                policy.append('"},')

        if matchAnyBucket:
            policy.append('["starts-with", "$bucket", ""],')

        if matchAnyKey:
            policy.append('["starts-with", "$key", ""],')

        policy.append(']}')

        originPolicy = ''.join(policy)

        policy = common_util.base64_encode(originPolicy)

        v4Auth = V4Authentication(self.access_key_id, self.secret_access_key, self.region, shortDate, longDate,
                                  self.path_style)

        signingKey = v4Auth.getSigningKey_python2() if IS_PYTHON2 else v4Auth.getSigningKey_python3()

        signature = v4Auth.hmacSha256(signingKey, policy if IS_PYTHON2 else policy.encode('UTF-8'))
        
        from com.obs.models.base_model import BaseModel
        class CreateV4PostSignatureResponse(BaseModel):
            allowedAttr = {'originPolicy': BASESTRING, 'policy': BASESTRING, 'credential': BASESTRING, 'date': BASESTRING, 'signature': BASESTRING}
        
        result = {'originPolicy': originPolicy ,'policy': policy, 'algorithm': formParams['X-Amz-Algorithm'], 'credential': formParams['X-Amz-Credential'], 'date': formParams['X-Amz-Date'], 'signature': signature}
        return CreateV4PostSignatureResponse(**result)

    @countTime
    def createBucket(self, bucketName, header=CreateBucketHeader(), location=None):
        self.log_client.log(INFO, 'enter createBucket ...')
        self.__assert_not_null(bucketName, 'bucketName is null')
        headers = {}
        if header is not None:
            if header.aclControl:
                headers['x-amz-acl'] = header.aclControl
            if header.storageClass:
                headers['x-default-storage-class'] = header.storageClass

        conn = self.__makePutRequest(bucketName, headers=headers, entity=None if location is None else convert_util.transLocationToXml(location))
        return GetResult.parse_xml(conn, connHolder=self.connHolder)

    @countTime
    def deleteBucket(self, bucketName):
        self.log_client.log(INFO, 'enter deleteBucket ...')
        self.__assert_not_null(bucketName, 'bucketName is null')
        conn = self.__makeDeleteRequest(bucketName, '')
        return GetResult.parse_xml(conn, connHolder=self.connHolder)

    @countTime
    def listBuckets(self):
        self.log_client.log(INFO, 'enter listBuckets ...')
        conn = self.__makeGetRequest()

        return GetResult.parse_xml(conn, 'listBuckets', connHolder=self.connHolder)

    @countTime
    def headBucket(self, bucketName):
        self.log_client.log(INFO, 'enter headBucket ...')
        self.__assert_not_null(bucketName, 'bucketName is null')
        conn = self.__makeHeadRequest(bucketName)

        return GetResult.parse_xml(conn, connHolder=self.connHolder)

    @countTime
    def getBucketMetadata(self, bucketName, origin=None, requestHeaders=None):
        self.log_client.log(INFO, 'enter getBucketMetadata ...')
        self.__assert_not_null(bucketName, 'bucketName is null')
        headers = {}
        if origin:
            headers['Origin'] = common_util.toString(origin)
        _requestHeaders = requestHeaders[0] if isinstance(requestHeaders,list) and len(requestHeaders) == 1 else requestHeaders
        if _requestHeaders:
            headers['Access-Control-Request-Headers'] = common_util.toString(_requestHeaders)
        conn = self.__makeHeadRequest(bucketName, headers=headers)
        return GetResult.parse_xml(conn, 'getBucketMetadata', connHolder=self.connHolder)

    @countTime
    def setBucketQuota(self, bucketName, quota):
        self.log_client.log(INFO, 'enter setBucketQuota ...')
        self.__assert_not_null(bucketName, 'bucketName is null')
        self.__assert_not_null(quota, 'quota is null')
        conn = self.__makePutRequest(bucketName, pathArgs={'quota': None}, entity=convert_util.transQuotaToXml(quota))
        return GetResult.parse_xml(conn, connHolder=self.connHolder)

    @countTime
    def getBucketQuota(self, bucketName):
        self.log_client.log(INFO, 'enter getBucketQuota ...')
        self.__assert_not_null(bucketName, 'bucketName is null')
        conn = self.__makeGetRequest(bucketName, pathArgs={'quota': None})
        return GetResult.parse_xml(conn, 'getBucketQuota', connHolder=self.connHolder)

    @countTime
    def getBucketStorageInfo(self , bucketName):
        self.log_client.log(INFO, 'enter getBucketStorageInfo ...')
        self.__assert_not_null(bucketName, 'bucketName is null')
        conn = self.__makeGetRequest(bucketName, pathArgs={'storageinfo': None})
        return GetResult.parse_xml(conn, 'getBucketStorageInfo', connHolder=self.connHolder)

    @countTime
    def setBucketAcl(self, bucketName, acl=ACL(), aclControl=None):
        self.log_client.log(INFO, 'enter setBucketAcl...')
        self.__assert_not_null(bucketName, 'bucketName is null')
        if acl is not None and len(acl) > 0 and aclControl is not None:
            raise Exception('Both acl and x_amz_acl are set')

        headers = None if aclControl is None else {'x-amz-acl': aclControl}

        entity = None if acl is None or len(acl) == 0 else convert_util.transAclToXml(acl)

        conn = self.__makePutRequest(bucketName,pathArgs={'acl': None}, headers=headers, entity=entity)
        return GetResult.parse_xml(conn, connHolder=self.connHolder)

    @countTime
    def getBucketAcl(self, bucketName):
        self.log_client.log(INFO, 'enter getBucketAcl...')
        self.__assert_not_null(bucketName, 'bucketName is null')
        conn = self.__makeGetRequest(bucketName, pathArgs={'acl': None})

        return GetResult.parse_xml(conn, 'getBucketAcl', connHolder=self.connHolder)

    @countTime
    def setBucketPolicy(self, bucketName, policyJSON):
        self.log_client.log(INFO, 'enter setBucketPolicy ...')
        self.__assert_not_null(bucketName, 'bucketName is null')
        self.__assert_not_null(policyJSON, 'policyJSON is null')
        conn = self.__makePutRequest(bucketName, pathArgs={'policy' : None}, entity=policyJSON)
        return GetResult.parse_xml(conn, connHolder=self.connHolder)

    @countTime
    def getBucketPolicy(self, bucketName):
        self.log_client.log(INFO, 'enter getBucketPolicy ...')
        self.__assert_not_null(bucketName, 'bucketName is null')

        conn = self.__makeGetRequest(bucketName, pathArgs={'policy' : None})
        return GetResult.parse_xml(conn,'getBucketPolicy', connHolder=self.connHolder)

    @countTime
    def deleteBucketPolicy(self, bucketName):
        self.log_client.log(INFO, 'enter deleteBucketPolicy ...')
        self.__assert_not_null(bucketName, 'bucketName is null')

        conn = self.__makeDeleteRequest(bucketName, pathArgs={'policy' : None})
        return GetResult.parse_xml(conn, connHolder=self.connHolder)

    @countTime
    def setBucketVersioningConfiguration(self, bucketName, status):
        self.log_client.log(INFO, 'enter setBucketVersioningConfiguration ...')
        self.__assert_not_null(bucketName, 'bucketName is null')
        self.__assert_not_null(status, 'status is null')
        conn = self.__makePutRequest(bucketName, pathArgs={'versioning' : None}, entity=convert_util.transVersionStatusToXml(status))

        return GetResult.parse_xml(conn, connHolder=self.connHolder)

    @countTime
    def getBucketVersioningConfiguration(self, bucketName):
        self.log_client.log(INFO, 'enter getBucketVersioningConfiguration ...')
        self.__assert_not_null(bucketName, 'bucketName is null')

        conn = self.__makeGetRequest(bucketName, pathArgs={'versioning' : None})

        return GetResult.parse_xml(conn,'getBucketVersioningConfiguration', connHolder=self.connHolder)

    @countTime
    def listVersions(self, bucketName, version=None):
        self.log_client.log(INFO, 'enter listVersions ...')
        self.__assert_not_null(bucketName, 'bucketName is null')
        path_args = {'versions' : None}
        if version:
            if version.prefix:
                path_args['prefix'] = version.prefix
            if version.key_marker:
                path_args['key-marker'] = version.key_marker
            if version.max_keys:
                path_args['max-keys'] = version.max_keys
            if version.delimiter:
                path_args['delimiter'] = version.delimiter
            if version.version_id_marker:
                path_args['version-id-marker'] = version.version_id_marker


        conn = self.__makeGetRequest(bucketName, pathArgs=path_args)

        return GetResult.parse_xml(conn, 'listVersions', connHolder=self.connHolder)

    @countTime
    def listObjects(self, bucketName, prefix=None, marker=None, max_keys=None, delimiter=None):
        self.log_client.log(INFO, 'enter listObjects ...')
        self.__assert_not_null(bucketName, 'bucketName is null')
        path_args = {}
        if prefix:
            path_args['prefix'] = prefix
        if marker:
            path_args['marker'] = marker
        if delimiter:
            path_args['delimiter'] = delimiter
        if max_keys:
            path_args['max-keys'] = max_keys
        conn = self.__makeGetRequest(bucketName, pathArgs=path_args)
        return GetResult.parse_xml(conn,'listObjects', connHolder=self.connHolder)

    @countTime
    def listMultipartUploads(self, bucketName, multipart=ListMultipartUploadsRequest()):
        self.log_client.log(INFO, 'enter listMultipartUploads ...')
        self.__assert_not_null(bucketName, 'bucketName is null')
        path_args = multipart.params_multipart_for_dict_options() if multipart is not None else {'uploads': None}

        conn = self.__makeGetRequest(bucketName, pathArgs=path_args)

        return GetResult.parse_xml(conn,'listMultipartUploads', connHolder=self.connHolder)

    @countTime
    def deleteBucketLifecycleConfiguration(self, bucketName):
        self.log_client.log(INFO, 'enter deleteBucketLifecycleConfiguration ...')
        self.__assert_not_null(bucketName, 'bucketName is null')
        conn = self.__makeDeleteRequest(bucketName, pathArgs={'lifecycle':None})

        return GetResult.parse_xml(conn, connHolder=self.connHolder)

    @countTime
    def setBucketLifecycleConfiguration(self, bucketName, lifecycle):
        self.log_client.log(INFO, 'enter setBucketLifecycleConfiguration ...')
        self.__assert_not_null(bucketName, 'bucketName is null')
        self.__assert_not_null(lifecycle, 'lifecycle is null')

        entity = convert_util.transLifecycleToXml(lifecycle)
        base64_md5 = common_util.base64_encode(common_util.md5_encode(entity))
        headers = {'Content-MD5' : base64_md5}

        conn = self.__makePutRequest(bucketName, pathArgs={'lifecycle':None}, headers=headers, entity=entity)
        return GetResult.parse_xml(conn, connHolder=self.connHolder)

    @countTime
    def getBucketLifecycleConfiguration(self, bucketName):
        self.log_client.log(INFO, 'enter getBucketLifecycleConfiguration ...')
        self.__assert_not_null(bucketName, 'bucketName is null')

        conn = self.__makeGetRequest(bucketName, pathArgs={'lifecycle':None})

        return GetResult.parse_xml(conn, 'getBucketLifecycleConfiguration', connHolder=self.connHolder)

    @countTime
    def deleteBucketWebsiteConfiguration(self, bucketName):
        self.log_client.log(INFO, 'enter deleteBucketWebsiteConfiguration ...')
        self.__assert_not_null(bucketName, 'bucketName is null')
        conn = self.__makeDeleteRequest(bucketName, pathArgs={'website':None})
        return GetResult.parse_xml(conn, connHolder=self.connHolder)

    @countTime
    def setBucketWebsiteConfiguration(self, bucketName, website):
        self.log_client.log(INFO, 'enter setBucketWebsiteConfiguration ...')
        self.__assert_not_null(bucketName, 'bucketName is null')
        self.__assert_not_null(website, 'website is null')

        conn = self.__makePutRequest(bucketName, pathArgs={'website':None},entity=convert_util.transWebsiteToXml(website))
        return GetResult.parse_xml(conn, connHolder=self.connHolder)

    @countTime
    def getBucketWebsiteConfiguration(self, bucketName):
        self.log_client.log(INFO, 'enter getBucketWebsiteConfiguration ...')
        self.__assert_not_null(bucketName, 'bucketName is null')
        conn = self.__makeGetRequest(bucketName, pathArgs={'website':None})
        return GetResult.parse_xml(conn, 'getBucketWebsiteConfiguration', connHolder=self.connHolder)

    @countTime
    def setBucketLoggingConfiguration(self, bucketName, logstatus=Logging()):
        self.log_client.log(INFO, 'enter setBucketLoggingConfiguration...')
        self.__assert_not_null(bucketName, 'bucketName is null')
        self.__assert_not_null(bucketName, 'logstatus is null')
        conn = self.__makePutRequest(bucketName, pathArgs={'logging':None}, entity=convert_util.transLoggingToXml(logstatus))
        return GetResult.parse_xml(conn, connHolder=self.connHolder)

    @countTime
    def getBucketLoggingConfiguration(self, bucketName):
        self.log_client.log(INFO, 'enter getbucketLoggingConfiguration ...')
        self.__assert_not_null(bucketName, 'bucketName is null')
        conn = self.__makeGetRequest(bucketName, pathArgs={'logging':None})
        return GetResult.parse_xml(conn,'getBucketLoggingConfiguration', connHolder=self.connHolder)

    @countTime
    def getBucketLocation(self, bucketName):
        self.log_client.log(INFO, 'enter getBucketLocation ...')
        self.__assert_not_null(bucketName, 'bucketName is null')
        conn = self.__makeGetRequest(bucketName, pathArgs={'location':None})
        return GetResult.parse_xml(conn, 'getBucketLocation', connHolder=self.connHolder)

    @countTime
    def getBucketTagging(self, bucketName):
        self.log_client.log(INFO, 'enter getBucketTagging...')
        self.__assert_not_null(bucketName, 'bucketName is null')
        conn = self.__makeGetRequest(bucketName, pathArgs={'tagging' : None})
        return GetResult.parse_xml(conn, 'getBucketTagging', connHolder=self.connHolder)

    @countTime
    def setBucketTagging(self,bucketName,tagInfo):
        self.log_client.log(INFO, 'enter setBucketTagging...')
        self.__assert_not_null(bucketName, 'bucketName is null')
        self.__assert_not_null(tagInfo, 'tagInfo is null')
        entity = convert_util.transTagInfoToXml(tagInfo)
        base64_md5 = common_util.base64_encode(common_util.md5_encode(entity))
        headers = {'Content-MD5': base64_md5}
        conn = self.__makePutRequest(bucketName, pathArgs={'tagging' : None}, headers=headers, entity=entity)
        return GetResult.parse_xml(conn, connHolder=self.connHolder)

    @countTime
    def deleteBucketTagging(self, bucketName):
        self.log_client.log(INFO, 'enter deleteBucketTagging...')
        self.__assert_not_null(bucketName, 'bucketName is null')
        conn = self.__makeDeleteRequest(bucketName, pathArgs={'tagging' : None})
        return GetResult.parse_xml(conn, connHolder=self.connHolder)

    @countTime
    def setBucketCors(self, bucketName, corsRuleList):
        self.log_client.log(INFO, 'enter setBucketCors...')
        self.__assert_not_null(bucketName, 'bucketName is null')
        self.__assert_not_null(corsRuleList, 'corsRuleList is null')
        entity = convert_util.transCorsRuleToXml(corsRuleList)
        md5 = common_util.md5_encode(entity)
        base64_md5 = common_util.base64_encode(md5)
        headers = {'Content-MD5': base64_md5}
        conn = self.__makePutRequest(bucketName, pathArgs={'cors' : None}, headers=headers, entity=entity)
        return GetResult.parse_xml(conn, connHolder=self.connHolder)

    @countTime
    def deleteBucketCors(self, bucketName):
        self.log_client.log(INFO, 'enter deleteBucketCors...')
        self.__assert_not_null(bucketName, 'bucketName is null')
        conn = self.__makeDeleteRequest(bucketName, pathArgs={'cors' : None})
        return GetResult.parse_xml(conn, connHolder=self.connHolder)

    @countTime
    def getBucketCors(self, bucketName):
        self.log_client.log(INFO, 'enter getBucketCors...')
        self.__assert_not_null(bucketName, 'bucketName is null')
        conn = self.__makeGetRequest(bucketName, pathArgs={'cors': None})
        return GetResult.parse_xml(conn,'getBucketCors', connHolder=self.connHolder)

    @countTime
    def optionsBucket(self, bucketName, option):
        self.log_client.log(INFO, 'enter optionsBucket...')
        self.__assert_not_null(bucketName, 'bucketName is null')
        headers = {}
        if option is not None:
            if option.origin:
                headers['Origin'] = option.origin
            if option.accessControlRequestMethods:
                headers['Access-Control-Request-Method'] = option.accessControlRequestMethods
            if option.accessControlRequestHeaders:
                headers['Access-Control-Request-Headers'] = option.accessControlRequestHeaders

        conn = self.__makeOptionsRequest(bucketName, headers=headers)
        return GetResult.parse_xml(conn, 'optionsBucket', connHolder=self.connHolder)

    @countTime
    def setBucketNotification(self,bucketName, notification=Notification()):
        self.log_client.log(INFO, 'enter setBucketNotification...')
        self.__assert_not_null(bucketName, 'bucketName is null')
        self.__assert_not_null(notification, 'notification is null')
        conn = self.__makePutRequest(bucketName, pathArgs={'notification': None}, entity=convert_util.transNotificationToXml(notification))
        return GetResult.parse_xml(conn, connHolder=self.connHolder)

    @countTime
    def getBucketNotification(self, bucketName):
        self.log_client.log(INFO, 'enter getBucketNotification...')
        self.__assert_not_null(bucketName, 'bucketName is null')
        conn = self.__makeGetRequest(bucketName, pathArgs={'notification': None})
        return GetResult.parse_xml(conn, 'getBucketNotification', connHolder=self.connHolder)

    @countTime
    def optionsObject(self, bucketName, objectKey, option):
        self.log_client.log(INFO, 'enter optionsObject...')
        self.__assert_not_null(bucketName, 'bucketName is null')
        headers = {}
        if option is not None:
            if option.origin:
                headers['Origin'] = option.origin
            if option.accessControlRequestMethods:
                headers['Access-Control-Request-Method'] = option.accessControlRequestMethods
            if option.accessControlRequestHeaders:
                headers['Access-Control-Request-Headers'] = option.accessControlRequestHeaders

        conn = self.__makeOptionsRequest(bucketName, objectKey, headers=headers)
        return GetResult.parse_xml(conn, 'optionsBucket', connHolder=self.connHolder)

    @countTime
    def getObjectMetadata(self, bucketName, objectKey, versionId=None, sseHeader=SseHeader(), origin=None, requestHeaders=None):
        self.log_client.log(INFO, 'enter getObjectMetadata...')
        self.__assert_not_null(bucketName, 'bucketName is null')
        path_args = {}
        if versionId:
            path_args['versionId'] = versionId
        headers = {}
        if origin:
            headers['Origin'] = common_util.toString(origin)
        _requestHeaders = requestHeaders[0] if isinstance(requestHeaders,list) and len(requestHeaders) == 1 else requestHeaders
        if _requestHeaders:
            headers['Access-Control-Request-Headers'] = common_util.toString(_requestHeaders)
        conn = self.__makeHeadRequest(bucketName, objectKey, pathArgs=path_args, headers=self.__setSseHeader(sseHeader, headers=headers, onlySseCHeader=True))
        return GetResult.parse_xml(conn, 'getObjectMetadata', connHolder=self.connHolder)

    @countTime
    def getObject(self , bucketName, objectKey, downloadPath=None, getObjectRequest=GetObjectRequest(), headers=GetObjectHeader(), loadStreamInMemory=False):
        self.log_client.log(INFO, 'enter getObject ...')
        self.__assert_not_null(bucketName, 'bucketName is null')
        pathArgs = {}
        if getObjectRequest is not None and len(getObjectRequest) > 0:
            if getObjectRequest.cache_control is not None:
                pathArgs['response-cache-control'] = getObjectRequest.cache_control
            if getObjectRequest.content_disposition is not None:
                pathArgs['response-content-disposition'] = getObjectRequest.content_disposition
            if getObjectRequest.content_encoding is not None:
                pathArgs['response-content-encoding'] = getObjectRequest.content_encoding
            if getObjectRequest.content_language is not None:
                pathArgs['response-content-language'] = getObjectRequest.content_language
            if getObjectRequest.content_type is not None:
                pathArgs['response-content-type'] = getObjectRequest.content_type
            if getObjectRequest.expires is not None:
                pathArgs['response-expires'] = getObjectRequest.expires
            if getObjectRequest.versionId is not None:
                pathArgs['versionId'] = getObjectRequest.versionId

        _headers = {}
        if headers is not None and len(headers) > 0:
            if headers.range:
                _headers['Range'] = 'bytes=' + headers.range
            if headers.if_modified_since:
                _headers['If-Modified-Since'] = headers.if_modified_since.ToGMTTime() if isinstance(headers.if_modified_since, DateTime) else headers.if_modified_since
            if headers.if_unmodified_since:
                _headers['If-Unmodified-Since'] = headers.if_unmodified_since.ToGMTTime() if isinstance(headers.if_unmodified_since, DateTime) else headers.if_unmodified_since
            if headers.if_match:
                _headers['If-Match'] = headers.if_match
            if headers.if_none_match:
                _headers['If-None-Match'] = headers.if_none_match
            if headers.origin:
                _headers['Origin'] = headers.origin
            if headers.requestHeaders:
                _headers['Access-Control-Request-Headers'] = headers.requestHeaders
            if headers.sseHeader:
                self.__setSseHeader(headers.sseHeader,_headers, True)
        conn = self.__makeGetRequest(bucketName, objectKey, pathArgs=pathArgs, headers=_headers)
        return GetResult.parse_content(conn, objectKey, downloadPath, self.chunk_size, loadStreamInMemory, connHolder=self.connHolder)

    @countTime
    def putContent(self, bucketName, objectKey, content=None, metadata=None, headers=PutObjectHeader()):
        self.log_client.log(INFO, 'enter putContent...')
        self.__assert_not_null(bucketName, 'bucketName is null')
        self.__assert_not_null(objectKey, 'objectKey is null')
        if content is None:
            content = ''

        if headers is None:
            headers = PutObjectHeader()
        
        if headers.contentType is None:
            headers.contentType = common_util.MIME_TYPES.get(objectKey[objectKey.rfind('.') + 1:])
        _headers = self.__assembleHeadersForPutObject(metadata=metadata, headers=headers)

        if content is not None and hasattr(content, 'read') and callable(content.read):
            CHUNKSIZE = self.chunk_size
            if headers.contentLength is None:
                self.log_client.log(DEBUG, 'missing content-length when uploading a readable stream')
                conn = self.__makePutRequest(bucketName, objectKey, headers=_headers, chunked_mode=True)
                while True:
                    chunk = content.read(CHUNKSIZE)
                    if not chunk:
                        conn.send('0\r\n\r\n' if IS_PYTHON2 else '0\r\n\r\n'.encode('UTF-8'))
                        break
                    hex_chunk = hex(len(chunk))[2:]
                    conn.send(hex_chunk if IS_PYTHON2 else hex_chunk.encode('UTF-8'))
                    conn.send('\r\n' if IS_PYTHON2 else '\r\n'.encode('UTF-8'))
                    conn.send(chunk)
            else:
                conn = self.__makePutRequest(bucketName, objectKey, headers=_headers)
                readCount = 0
                totalCount = common_util.toLong(headers.contentLength)
                while True:
                    if readCount >= totalCount:
                        break
                    readCountOnce = CHUNKSIZE if totalCount - readCount >= CHUNKSIZE else totalCount - readCount
                    chunk = content.read(readCountOnce)
                    if not chunk:
                        break
                    conn.send(chunk)
                    readCount = readCount + readCountOnce
            if hasattr(content, 'close') and callable(content.close):
                content.close()
        else:
            conn = self.__makePutRequest(bucketName, objectKey, headers=_headers, entity=content)
        return GetResult.parse_xml(conn, 'putContent',connHolder=self.connHolder)

    def putObject(self, bucketName, objectKey, content, metadata=None, headers=PutObjectHeader()):
        print('This function "putObject" is deprecated, please use function "putContent" instead')
        return self.putContent(bucketName, objectKey, content, metadata, headers)

    @countTime
    def putFile(self, bucketName, objectKey, file_path, metadata=None, headers=PutObjectHeader()):
        self.log_client.log(INFO, 'enter postObject...')
        self.__assert_not_null(bucketName, 'bucketName is null')
        file_path = common_util.safe_encode(file_path)
        if not os.path.exists(file_path):
            file_path = common_util.safe_trans_to_gb2312(file_path)
            if not os.path.exists(file_path):
                raise Exception('file [{0}] doesnot exist'.format(file_path))

        _flag = os.path.isdir(file_path)

        if headers is None:
            headers = PutObjectHeader()

        if _flag:
            headers.contentLength = None
            headers.md5 = None
            headers.contentType = None

            results = []
            for f in os.listdir(file_path):  # windows中文文件路径
                f = common_util.safe_encode(f)
                __file_path = os.path.join(file_path, f)
                if not objectKey:
                    key = common_util.safe_trans_to_utf8('{0}/'.format(os.path.split(file_path)[1]) + f)
                else:
                    key = '{0}/'.format(objectKey) + common_util.safe_trans_to_utf8(f)
                result = self.putFile(bucketName, key, __file_path, metadata, headers)
                results.append((key, result))
            return results

        if not objectKey:
            objectKey = os.path.split(file_path)[1]

        size = os.path.getsize(file_path)
        if headers.contentLength is not None:
            headers.contentLength = size if common_util.toLong(headers.contentLength) > common_util.toLong(size) else headers.contentLength

        if headers.contentType is None:
            headers.contentType = common_util.MIME_TYPES.get(objectKey[objectKey.rfind('.') + 1:])

        if headers.contentType is None:
            headers.contentType = common_util.MIME_TYPES.get(file_path[file_path.rfind('.') + 1:])

        _headers = self.__assembleHeadersForPutObject(metadata=metadata, headers=headers)
        if 'Content-Length' not in _headers:
            _headers['Content-Length'] = common_util.toString(size)
        conn = self.__makePutRequest(bucketName, objectKey, headers=_headers)
        self.log_client.log(DEBUG, 'send Path:%s' % file_path)

        CHUNKSIZE = self.chunk_size
        if headers.contentLength:
            readCount = 0
            totalCount = common_util.toLong(headers.contentLength)
            with open(file_path, 'rb') as f:
                while True:
                    if readCount >= totalCount:
                        break
                    readCountOnce = CHUNKSIZE if totalCount - readCount >= CHUNKSIZE else totalCount - readCount
                    chunk = f.read(readCountOnce)
                    if not chunk:
                        break
                    conn.send(chunk)
                    readCount = readCount + readCountOnce
        else:
            with open(file_path, 'rb') as f:
                while True:
                    chunk = f.read(CHUNKSIZE)
                    if not chunk:
                        break
                    conn.send(chunk)

        return GetResult.parse_xml(conn, 'putContent',connHolder=self.connHolder)

    def postObject(self, bucketName, objectKey, file_path, metadata=None, headers=PutObjectHeader()):
        print('This function "postObject" is deprecated, please use function "putFile" instead')
        return self.putFile(bucketName, objectKey, file_path, metadata, headers)

    @countTime
    def copyObject(self, sourceBucketName, sourceObjectKey, destBucketName, destObjectKey, metadata=None, headers=CopyObjectHeader(), versionId=None):
        self.log_client.log(INFO, 'enter copyObject...')
        self.__assert_not_null(sourceBucketName, 'sourceBucketName is null')
        self.__assert_not_null(sourceObjectKey, 'sourceObjectKey is null')
        self.__assert_not_null(destBucketName, 'destBucketName is null')
        self.__assert_not_null(destObjectKey, 'destObjectKey is null')
        _headers = {}
        if metadata:
            for k, v in metadata.items():
                if not common_util.toString(k).lower().startswith('x-amz-'):
                    k = 'x-amz-meta-' + k
                _headers[k] = v

        copy_source = '/%s/%s' % (sourceBucketName, sourceObjectKey)
        if versionId:
            copy_source += '?versionId=%s' % (versionId)
        _headers['x-amz-copy-source'] = copy_source

        if headers is not None and len(headers) > 0:
            if headers.acl:
                _headers['x-amz-acl'] = headers.acl
            if headers.directive :
                _headers['x-amz-metadata-directive'] = headers.directive
            if headers.if_match:
                _headers['x-amz-copy-source-if-match'] = headers.if_match
            if headers.if_none_match:
                _headers['x-amz-copy-source-if-none-match'] = headers.if_none_match
            if headers.if_modified_since:
                _headers['x-amz-copy-source-if-modified-since'] = headers.if_modified_since.ToGMTTime() if isinstance(headers.if_modified_since, DateTime) else headers.if_modified_since
            if headers.if_unmodified_since:
                _headers['x-amz-copy-source-if-unmodified-since'] = headers.if_unmodified_since.ToGMTTime() if isinstance(headers.if_unmodified_since, DateTime) else headers.if_unmodified_since
            if headers.location:
                _headers['x-amz-website-redirect-location'] = headers.location
            
            if headers.cacheControl:
                _headers['cache-control'] = headers.cacheControl
            if headers.contentDisposition:
                _headers['content-disposition'] = headers.contentDisposition
            if headers.contentEncoding:
                _headers['content-encoding'] = headers.contentEncoding
            if headers.contentLanguage:
                _headers['content-language'] = headers.contentLanguage
            if headers.contentType:
                _headers['content-type'] = headers.contentType
            if headers.expires:
                _headers['expires'] = headers.expires
                                            
            if headers.destSseHeader:
                self.__setSseHeader(headers.destSseHeader, _headers)
            if headers.sourceSseHeader:
                self.__setSourceSseHeader(headers.sourceSseHeader, _headers)
        conn = self.__makePutRequest(destBucketName, destObjectKey, headers=_headers)
        return GetResult.parse_xml(conn, 'copyObject', connHolder=self.connHolder)

    @countTime
    def setObjectAcl(self, bucketName, objectKey, acl=ACL(), versionId=None, aclControl=None):
        self.log_client.log(INFO, 'enter setObjectAcl ...')
        self.__assert_not_null(bucketName, 'bucketName is null')
        if acl is not None and len(acl) > 0 and aclControl is not None:
            raise Exception('Both acl and aclControl are set')

        path_args = {'acl': None}
        if versionId:
            path_args['versionId'] = common_util.toString(versionId)

        headers = None if aclControl is None else {'x-amz-acl': aclControl}

        entity = None if acl is None or len(acl) == 0 else convert_util.transAclToXml(acl)
        conn = self.__makePutRequest(bucketName, objectKey, pathArgs=path_args, headers=headers, entity=entity)

        return GetResult.parse_xml(conn, connHolder=self.connHolder)

    @countTime
    def getObjectAcl(self, bucketName, objectKey, versionId=None):
        self.log_client.log(INFO, 'enter getObjectAcl ...')
        self.__assert_not_null(bucketName, 'bucketName is null')

        path_args = {'acl': None}
        if versionId:
            path_args['versionId'] = common_util.toString(versionId)

        conn = self.__makeGetRequest(bucketName, objectKey, pathArgs=path_args)
        return GetResult.parse_xml(conn, 'getObjectAcl', connHolder=self.connHolder)

    @countTime
    def deleteObject(self , bucketName, objectKey, versionId=None):
        self.log_client.log(INFO, 'enter deleteObject ...')
        self.__assert_not_null(bucketName, 'bucketName is null')
        self.__assert_not_null(objectKey, 'objectKey is null')
        path_args = {}
        if versionId:
            path_args['versionId'] = common_util.toString(versionId)
        conn = self.__makeDeleteRequest(bucketName, objectKey, pathArgs=path_args)
        return GetResult.parse_xml(conn, 'deleteObject', connHolder=self.connHolder)

    @countTime
    def deleteObjects(self, bucketName, deleteObjectsRequest):
        self.log_client.log(INFO, 'enter deleteObjects ...')
        self.__assert_not_null(bucketName, 'bucketName is null')
        self.__assert_not_null(deleteObjectsRequest, 'deleteObjectsRequest is null')

        entity = convert_util.transDeleteObjectsRequestToXml(deleteObjectsRequest)
        base64_md5 = common_util.base64_encode(common_util.md5_encode(entity))
        headers = {'Content-MD5': base64_md5}
        conn = self.__makePostRequest(bucketName, pathArgs={'delete': None}, headers=headers, entity=entity)
        return GetResult.parse_xml(conn, 'deleteObjects', connHolder=self.connHolder)

    @countTime
    def restoreObject(self, bucketName, objectKey, days, tier=None, versionId=None):
        self.log_client.log(INFO, 'enter restoreObject ...')
        self.__assert_not_null(bucketName, 'bucketName is null')
        self.__assert_not_null(objectKey, 'objectKey is null')
        self.__assert_not_null(days, 'days is null')

        path_args = {'restore': None}
        if versionId:
            path_args['versionId'] = common_util.toString(versionId)

        restore = Restore(days=days, tier=tier)
        entity = convert_util.transRestoreToXml(restore)
        base64_md5 = common_util.base64_encode(common_util.md5_encode(entity))
        headers = {'Content-MD5': base64_md5}
        conn = self.__makePostRequest(bucketName, objectKey, pathArgs=path_args, headers=headers, entity=entity)
        return GetResult.parse_xml(conn, connHolder=self.connHolder)

    @countTime
    def initiateMultipartUpload(self, bucketName, objectKey, acl=None, metadata=None, websiteRedirectLocation=None, contentType=None, sseHeader=SseHeader()):
        self.log_client.log(INFO, 'enter initiateMultipartUpload ...')
        self.__assert_not_null(bucketName, 'bucketName is null')
        self.__assert_not_null(objectKey, 'objectKey is null')
        headers = {}
        if acl:
            headers['x-amz-acl'] = acl
        if metadata:
            for k, v in metadata.items():
                if not common_util.toString(k).lower().startswith('x-amz-'):
                    k = 'x-amz-meta-' + k
                headers[k] = v
        if websiteRedirectLocation:
            headers['x-amz-website-redirect-location'] = websiteRedirectLocation
        if contentType:
            headers['Content-Type'] = contentType
        else:
            headers['Content-Type'] = common_util.MIME_TYPES.get(objectKey[objectKey.rfind('.') + 1:])
            
        if sseHeader:
            self.__setSseHeader(sseHeader, headers)
        conn = self.__makePostRequest(bucketName, objectKey, pathArgs={'uploads': None}, headers=headers)
        return GetResult.parse_xml(conn, 'initiateMultipartUpload', connHolder=self.connHolder)

    @countTime
    def uploadPart(self, bucketName, objectKey, partNumber, uploadId, object, isFile=False, partSize=None, offset=0, sseHeader=SseHeader(), isAttachMd5=False, md5=None):
        self.log_client.log(INFO, 'enter uploadPart ...')
        self.__assert_not_null(bucketName, 'bucketName is null')
        self.__assert_not_null(objectKey, 'objectKey is null')
        self.__assert_not_null(partNumber, 'partNumber is null')
        self.__assert_not_null(uploadId, 'uploadId is null')
        self.__assert_not_null(object, 'object is null')

        path_args = {'partNumber': partNumber, 'uploadId': uploadId}
        if isFile:
            file_path = common_util.safe_encode(object)
            if not os.path.exists(file_path):
                file_path = common_util.safe_trans_to_gb2312(file_path)
                if not os.path.exists(file_path):
                    raise Exception('file [{0}] does not exist'.format(file_path))
            file_size = os.path.getsize(file_path)
            offset = common_util.toLong(offset)
            offset = offset if offset is not None and 0 <= offset < file_size else 0
            partSize = common_util.toLong(partSize)
            partSize = partSize if partSize is not None and 0 < partSize <= (file_size - offset) else file_size - offset

            headers = {'Content-Length' : common_util.toString(partSize)}

            if md5:
                headers['Content-MD5'] = md5
            elif isAttachMd5:
                headers['Content-MD5'] = common_util.base64_encode(common_util.md5_file_encode_by_size_offset(file_path, partSize, offset, self.chunk_size))

            if sseHeader:
                self.__setSseHeader(sseHeader, headers, True)

            conn = self.__makePutRequest(bucketName, objectKey, pathArgs=path_args, headers=headers)
            with open(file_path, 'rb') as f:
                CHUNKSIZE = self.chunk_size
                readCount = 0
                f.seek(offset)
                while readCount < partSize:
                    read_size = CHUNKSIZE if partSize - readCount >= CHUNKSIZE else partSize - readCount
                    chunk = f.read(read_size)
                    readCountOnce = len(chunk)
                    if readCountOnce <= 0:
                        break
                    conn.send(chunk)
                    readCount += readCountOnce
        else:
            if object is not None and hasattr(object, 'read') and callable(object.read):
                CHUNKSIZE = self.chunk_size
                
                headers = {}
                if md5:
                    headers['Content-MD5'] = md5
    
                if sseHeader:
                    self.__setSseHeader(sseHeader, headers, True)
                
                if partSize is None:
                    self.log_client.log(DEBUG, 'missing partSize when uploading a readable stream')
                    conn = self.__makePutRequest(bucketName, objectKey, pathArgs=path_args, headers=headers, chunked_mode=True)
                    while True:
                        chunk = object.read(CHUNKSIZE)
                        if not chunk:
                            conn.send('0\r\n\r\n')
                            break
                        conn.send(hex(len(chunk))[2:])
                        conn.send('\r\n')
                        conn.send(chunk)
                
                else:
                    headers['Content-Length'] = common_util.toString(partSize)
                    conn = self.__makePutRequest(bucketName, objectKey, pathArgs=path_args, headers=headers)
                    readCount = 0
                    totalCount = common_util.toLong(partSize)
                    while True:
                        if readCount >= totalCount:
                            break
                        readCountOnce = CHUNKSIZE if totalCount - readCount >= CHUNKSIZE else totalCount - readCount
                        chunk = object.read(readCountOnce)
                        if not chunk:
                            break
                        conn.send(chunk)
                        readCount = readCount + readCountOnce
                if hasattr(object, 'close') and callable(object.close):
                    object.close()
            else:
                entity = common_util.toString(object)
                headers = {}
                if md5:
                    headers['Content-MD5'] = md5
                elif isAttachMd5:
                    headers['Content-MD5'] = common_util.base64_encode(common_util.md5_encode(entity))
                if sseHeader:
                    self.__setSseHeader(sseHeader, headers, True)
                conn = self.__makePutRequest(bucketName, objectKey, pathArgs=path_args, headers=headers, entity=entity)

        return GetResult.parse_xml(conn, 'uploadPart', connHolder=self.connHolder)

    @countTime
    def copyPart(self, bucketName, objectKey, partNumber, uploadId, copySource, copySourceRange=None, destSseHeader=SseHeader(), sourceSseHeader=SseHeader()):
        self.log_client.log(INFO, 'enter copyPart ...')
        self.__assert_not_null(bucketName, 'bucketName is null')
        self.__assert_not_null(objectKey, 'objectKey is null')
        self.__assert_not_null(partNumber, 'partNumber is null')
        self.__assert_not_null(uploadId, 'uploadId is null')
        self.__assert_not_null(copySource, 'copySource is null')
        path_args = {'partNumber': partNumber, 'uploadId': uploadId}
        headers = {'x-amz-copy-source': common_util.encode_item(copySource, ',:?/=+&%')}
        if copySourceRange:
            headers['x-amz-copy-source-range'] = 'bytes=' + common_util.toString(copySourceRange)
        if destSseHeader:
            self.__setSseHeader(destSseHeader, headers)
        if sourceSseHeader:
            self.__setSourceSseHeader(sourceSseHeader, headers)
        conn = self.__makePutRequest(bucketName, objectKey, pathArgs=path_args, headers=headers)
        return GetResult.parse_xml(conn, 'copyPart', connHolder=self.connHolder)

    @countTime
    def completeMultipartUpload(self, bucketName, objectKey, uploadId, completeMultipartUploadRequest):
        self.log_client.log(INFO, 'enter completeMultipartUpload ...')
        self.__assert_not_null(bucketName, 'bucketName is null')
        self.__assert_not_null(objectKey, 'objectKey is null')
        self.__assert_not_null(uploadId, 'uploadId is null')
        self.__assert_not_null(completeMultipartUploadRequest, 'completeMultipartUploadRequest is null')

        conn = self.__makePostRequest(bucketName, objectKey, pathArgs={'uploadId':uploadId},
                                      entity=convert_util.transCompleteMultipartUploadRequestToXml(completeMultipartUploadRequest))
        return GetResult.parse_xml(conn,'completeMultipartUpload', connHolder=self.connHolder)

    @countTime
    def abortMultipartUpload(self, bucketName, objectKey, uploadId):
        self.log_client.log(INFO, 'enter abortMultipartUpload ...')
        self.__assert_not_null(bucketName, 'bucketName is null')
        self.__assert_not_null(objectKey, 'objectKey is null')
        self.__assert_not_null(uploadId, 'uploadId is null')
        conn = self.__makeDeleteRequest(bucketName, objectKey, pathArgs={'uploadId' : uploadId})
        return GetResult.parse_xml(conn, connHolder=self.connHolder)

    @countTime
    def listParts(self, bucketName, objectKey, uploadId, maxParts=None, partNumberMarker=None):
        self.log_client.log(INFO, 'enter listParts ...')
        self.__assert_not_null(bucketName, 'bucketName is null')
        self.__assert_not_null(objectKey, 'objectKey is null')
        self.__assert_not_null(uploadId, 'uploadId is null')
        path_args = {'uploadId':uploadId}
        if maxParts:
            path_args['max-parts'] = maxParts
        if partNumberMarker:
            path_args['part-number-marker'] = partNumberMarker
        conn = self.__makeGetRequest(bucketName, objectKey, pathArgs=path_args)
        return GetResult.parse_xml(conn, 'listParts', connHolder=self.connHolder)


    def close(self):
        if self.connHolder is not None:
            self.connHolder['lock'].acquire()
            try:
                for conn in self.connHolder['connSet']:
                    if conn and hasattr(conn, 'close'):
                        try:
                            conn.close()
                        except Exception as ex:
                            self.log_client.log(WARNING, ex)
            finally:
                self.connHolder['lock'].release()
        
            del self.connHolder['lock']
            del self.connHolder['connSet']
        self.connHolder = None


    def __assembleHeadersForPutObject(self, metadata, headers):
        _headers = {}
        if metadata:
            for k, v in metadata.items():
                if not common_util.toString(k).lower().startswith('x-amz-'):
                    k = 'x-amz-meta-' + k
                _headers[k] = v
        if headers is not None and len(headers) > 0:
            if headers.md5 :
                _headers['Content-MD5'] = headers.md5
            if headers.acl :
                _headers['x-amz-acl'] = headers.acl
            if headers.location :
                _headers['x-amz-website-redirect-location'] = headers.location
            if headers.contentType:
                _headers['Content-Type'] = headers.contentType
            if headers.sseHeader:
                self.__setSseHeader(headers.sseHeader,_headers)
            if headers.contentLength is not None:
                _headers['Content-Length'] = common_util.toString(headers.contentLength)
        return _headers

    def __setSourceSseHeader(self, sseHeader, headers=None):
        if headers is None:
            headers = {}
        if isinstance(sseHeader, SseCHeader):
            headers['x-amz-copy-source-server-side-encryption-customer-algorithm'] = sseHeader.encryption
            key = common_util.toString(sseHeader.key).strip()
            headers['x-amz-copy-source-server-side-encryption-customer-key'] = common_util.base64_encode(key)
            headers['x-amz-copy-source-server-side-encryption-customer-key-MD5'] = common_util.base64_encode(common_util.md5_encode(key))
        return headers

    def __setSseHeader(self, sseHeader,headers=None, onlySseCHeader=False):
        if headers is None:
            headers = {}
        if isinstance(sseHeader, SseCHeader):
            headers['x-amz-server-side-encryption-customer-algorithm'] = sseHeader.encryption
            key = common_util.toString(sseHeader.key)
            headers['x-amz-server-side-encryption-customer-key'] = common_util.base64_encode(key)
            headers['x-amz-server-side-encryption-customer-key-MD5'] = common_util.base64_encode(common_util.md5_encode(key))
        if isinstance(sseHeader, SseKmsHeader) and not onlySseCHeader:
            headers['x-amz-server-side-encryption'] = sseHeader.encryption
            if sseHeader.key:
                headers['x-amz-server-side-encryption-aws-kms-key-id'] = key

        return headers

    def __makeOptionsRequest(self, bucketName, objectKey=None, pathArgs=None, headers=None):
        return self.__makeRequest('OPTIONS', bucketName, objectKey, pathArgs, headers)

    def __makeHeadRequest(self, bucketName, objectKey=None, pathArgs=None, headers=None):
        return self.__makeRequest('HEAD', bucketName, objectKey, pathArgs, headers)

    def __makeGetRequest(self, bucketName='', objectKey=None, pathArgs=None, headers=None):
        return self.__makeRequest('GET', bucketName, objectKey, pathArgs, headers)

    def __makeDeleteRequest(self, bucketName, objectKey=None, pathArgs=None, headers=None, entity=None):
        return self.__makeRequest('DELETE', bucketName, objectKey, pathArgs, headers, entity)

    def __makePostRequest(self, bucketName, objectKey=None, pathArgs=None, headers=None, entity=None, chunked_mode=False):
        return self.__makeRequest('POST', bucketName, objectKey, pathArgs, headers, entity, chunked_mode)

    def __makePutRequest(self, bucketName, objectKey=None, pathArgs=None, headers=None, entity=None, chunked_mode=False):
        return self.__makeRequest('PUT', bucketName, objectKey, pathArgs, headers, entity, chunked_mode)


    def __makeRequest(self, method, bucketName='', objectKey=None, pathArgs=None, headers=None, entity=None, chunked_mode=False):
        objectKey = common_util.safe_encode(objectKey)
        calling_format = self.calling_format if common_util.valid_subdomain_bucketname(bucketName) else RequestFormat.get_pathformat()

        if self.is_secure and not isinstance(calling_format, PathFormat) and bucketName.find('.') != -1:
            raise Exception('You are making an SSL connection, however, the bucket contains periods and \
                            the wildcard certificate will not match by default. Please consider using HTTP.')
        path = calling_format.get_url(bucketName, objectKey, pathArgs)

        port = None
        scheme = None
        if GetResult.CONTEXT and hasattr(GetResult.CONTEXT, 'location') and GetResult.CONTEXT.location:
            location = GetResult.CONTEXT.location
            location = urlparse(location)
            connect_server = location.hostname
            scheme = location.scheme
            port = location.port if location.port is not None else 80 if scheme.lower() == 'http' else 443
            GetResult.CONTEXT.location = None
            redirect = True

        else:
            connect_server = calling_format.get_server(self.server, bucketName)
            redirect = False

        headers = self.__rename_headers(headers, method)
        entity = common_util.safe_encode(entity)

        if entity is not None:
            if not isinstance(entity, str):
                entity = common_util.toString(entity)
            if not IS_PYTHON2:
                entity = entity.encode('UTF-8') if not isinstance(entity, bytes) else entity
            headers['Content-Length'] = common_util.toString(len(entity))

        headers['Host'] = connect_server
        header_config = self.__add_auth_headers(headers, method, bucketName, objectKey, pathArgs)

        header_log = header_config.copy()
        header_log['Host'] = '******'
        header_log['Authorization'] = '******'
        self.log_client.log(DEBUG, 'method:%s, path:%s, header:%s', method, path, header_log)
        conn = self.__send_request(connect_server, method, path, header_config, entity, port, scheme, redirect, chunked_mode)
        return conn

    def __add_auth_headers(self, headers, method, bucketName, objectKey, pathArgs):
        if IS_PYTHON2:
            imp.acquire_lock()
            try:
                from datetime import datetime
            finally:
                imp.release_lock()
        else:
            from datetime import datetime

        if 'x-amz-date' in headers:
            headers['Date'] = datetime.strptime(headers['x-amz-date'], common_util.LONG_DATE_FORMAT).strftime(common_util.GMT_DATE_FORMAT)
        elif 'X-Amz-Date' in headers:
            headers['Date'] = datetime.strptime(headers['X-Amz-Date'], common_util.LONG_DATE_FORMAT).strftime(common_util.GMT_DATE_FORMAT)
        elif 'date' not in headers or 'Date' not in headers:
            headers['Date'] = datetime.utcnow().strftime(common_util.GMT_DATE_FORMAT)  # 用当前时间来生成datetime对象

        ak = self.access_key_id
        sk = self.secret_access_key

        if self.signature.lower() == 'v4':
            date = headers['Date'] if 'Date' in headers else headers['date']
            date = datetime.strptime(date, common_util.GMT_DATE_FORMAT)
            shortDate = date.strftime(common_util.SHORT_DATE_FORMAT)
            longDate = date.strftime(common_util.LONG_DATE_FORMAT)
            v4 = V4Authentication(ak, sk, str(self.region) if self.region is not None else '', shortDate, longDate, self.path_style)
            auth = v4.v4Auth(method, bucketName, objectKey, pathArgs, headers)
        else:
            if 'Content-Type' not in headers and 'content-type' not in headers:
                headers['Content-Type'] = ''
            v2 = V2Authentication(ak, sk, self.path_style)
            auth = v2.v2Auth(method, bucketName, objectKey, pathArgs, headers)
        headers['Authorization'] = auth
        return headers

    def __rename_headers(self, headers, method):
        new_headers = {}
        if isinstance(headers, dict):
            for k, v in headers.items():
                if k is not None and v is not None:
                    k = str(k).strip()
                    if k.lower() not in common_util.ALLOWED_REQUEST_HTTP_HEADER_METADATA_NAMES and not k.lower().startswith(common_util.AMAZON_HEADER_PREFIX):
                        if method in ('PUT', 'POST'):
                            k = common_util.METADATA_PREFIX + k
                        else:
                            continue
                    new_headers[k] = v if isinstance(v, list) else common_util.encode_item(v, ' ,:?/+=%')
        return new_headers

    def __get_server_connection(self, server, port=None, scheme=None, redirect=False):

        if self.connHolder is not None and len(self.connHolder['connSet']) > 0:
            self.connHolder['lock'].acquire()
            try:
                return self.connHolder['connSet'].pop()
            finally:
                self.connHolder['lock'].release()
            
        is_secure = self.is_secure if scheme is None else True if scheme == 'https' else False

        if is_secure:
            self.log_client.log(DEBUG, 'is ssl_verify: %s', self.ssl_verify)
            if IS_PYTHON2:
                try:
                    conn = httplib.HTTPSConnection(server, port=port if port is not None else self.port, timeout=self.timeout, context=self.context)
                except: 
                    conn = httplib.HTTPSConnection(server, port=port if port is not None else self.port, timeout=self.timeout)
            else:
                conn = httplib.HTTPSConnection(server, port=port if port is not None else self.port, timeout=self.timeout, context=self.context, check_hostname=False)
        else:
            conn = httplib.HTTPConnection(server, port=port if port is not None else self.port, timeout=self.timeout)

        return conn

    def __send_request(self, server, method, path, header, entity=None, port=None, scheme=None, redirect=False, chunked_mode=False):

        flag = 0
        conn = None
        while True:
            try:
                conn = self.__get_server_connection(server, port, scheme, redirect)
                
                if header is None:
                    header = {}
                
                if self.long_conn_mode:
                    header['Connection'] = 'Keep-Alive'
                else:
                    header['Connection'] = 'close'
                
                if method == 'OPTIONS':
                    del header['Host']
                    conn.putrequest(method, path)
                    for k, v in header.items():
                        if k == 'Access-Control-Request-Method' and isinstance(v, list):
                            for item in v:
                                conn.putheader('Access-Control-Request-Method', item)
                        elif k == 'Access-Control-Request-Headers' and isinstance(v, list):
                            for item in v:
                                conn.putheader('Access-Control-Request-Headers', item)
                        else:
                            conn.putheader(k, v)
                    conn.endheaders()
                elif chunked_mode:
                    del header['Host']
                    header['Transfer-Encoding'] = 'chunked'
                    conn.putrequest(method, path)
                    for k, v in header.items():
                        conn.putheader(k, v)
                    conn.endheaders()
                else:
                    conn.request(method, path, headers=header)
            except socket.error as e:
                GetResult.closeConn(conn, self.connHolder)
                errno, errstr = sys.exc_info()[:2]
                if errno != socket.timeout or flag >= self.max_retry_count:
                    self.log_client.log(ERROR, 'connect service error, %s' % e)
                    raise e
                flag += 1
                self.log_client.log(WARNING, 'connect service time out,connect again,connect time:%d', int(flag))
                continue
            break

        if entity is not None:
            conn.send(entity)
        return conn