# -*- coding:utf-8 -*-
import os
import json
import markdown

from com.obs.client.obs_client import ObsClient
from com.obs.models.put_object_header import PutObjectHeader
from com.obs.models.get_object_header import GetObjectHeader
from com.obs.models.get_object_request import GetObjectRequest
from com.obs.response.get_result import ObjectStream
from com.obs.models.server_side_encryption import SseKmsHeader,SseCHeader
from com.obs.log.Log import *


TEMP_ROOT_PATH = "/tmp/"
region = 'china'
secure = True
signature = 'v4'
port = 443
path_style = True


def GetObject(obsAddr, bucketName, objName, ak, sk):

    TestObs = ObsClient(access_key_id=ak, secret_access_key=sk,
               is_secure=secure, server=obsAddr, signature=signature, path_style=path_style, region=region,ssl_verify=False, port=port,
               max_retry_count=5, timeout=20, chunk_size=65536)

    LobjectRequest = GetObjectRequest(content_type='application/zip', content_language=None, expires=None,
                                      cache_control=None, content_disposition=None, content_encoding=None,
                                      versionId=None)
    
    Lheaders = GetObjectHeader(range='', if_modified_since=None, if_unmodified_since=None, if_match=None,
                               if_none_match=None) 

    loadStreamInMemory = False
    resp = TestObs.getObject(bucketName=bucketName, objectKey=objName, downloadPath=TEMP_ROOT_PATH+objName,
                             getObjectRequest=LobjectRequest, headers=Lheaders, loadStreamInMemory=loadStreamInMemory)
    
    print('*** GetObject resp: ', resp)
    
    if isinstance(resp.body, ObjectStream):
        print '******'
        if loadStreamInMemory:
            print(resp.body.size)
        else:
            response = resp.body.response
            chunk_size = 65536
            if response is not None:
                while True:
                    chunk = response.read(chunk_size)
                    if not chunk:
                        break
                    print(chunk)
                response.close()
    else:
        pass #print(resp.body)
    
def PostObject(obsAddr, bucket, objName, ak, sk):
    TestObs = ObsClient(access_key_id=ak, secret_access_key=sk,
               is_secure=secure, server=obsAddr, signature=signature, path_style=path_style, region=region,ssl_verify=False, port=port,
               max_retry_count=5, timeout=20, chunk_size=65536)
 
    Lheaders = PutObjectHeader(md5=None, acl='private', location=None, contentType='text/plain')   

    Lheaders.sseHeader = SseKmsHeader.getInstance()
    h = PutObjectHeader()
    Lmetadata = {'key': 'value'}

    objPath = TEMP_ROOT_PATH + objName
    resp = TestObs.postObject(bucketName=bucket, objectKey=objName, file_path=objPath,
                              metadata=Lmetadata, headers=h)
    if isinstance(resp, list):
        for k, v in resp:
            print('PostObject, objectKey',k, 'common msg:status:', v.status, ',errorCode:', v.errorCode, ',errorMessage:', v.errorMessage)
    else:
        print('PostObject, common msg: status:', resp.status, ',errorCode:', resp.errorCode, ',errorMessage:', resp.errorMessage)

def getObsObjInfo4OBSTrigger(event):
    s3 = event['Records'][0]['s3']
    eventName = event['Records'][0]['eventName']
    bucket = s3['bucket']['name']
    objName = s3['object']['key']
    print "*** obsEventName: " + eventName
    print "*** srcBucketName: " + bucket
    print "*** srcObjName:" + objName
    return (bucket, objName)

def getObsObjInfo(event):
    msg = event['record'][0]['smn']['message']
    msg_event = json.loads(msg)
    record = msg_event['Records'][0]
    eventName = record['eventName']
    bucket = record['s3']['bucket']['name']
    objName = record['s3']['object']['key']
    print "*** obsEventName: " + eventName
    print "*** srcBucketName: " + bucket
    print "*** srcObjName:" + objName
    return (bucket, objName)

def markdown2Html(mdfile):
    exts = ['markdown.extensions.extra', 'markdown.extensions.codehilite','markdown.extensions.tables','markdown.extensions.toc']

    html = '''
    <html lang="zh-cn">
    <head>
    <meta content="text/html; charset=utf-8" http-equiv="content-type" />
    <link href="default.css" rel="stylesheet">
    <link href="github.css" rel="stylesheet">
    </head>
    <body>
    %s
    </body>
    </html>
    '''
    # 读取已经下载到临时目录中的markdown文件
    mdfilepath = TEMP_ROOT_PATH + mdfile
    infile = open(mdfilepath,'r')
    md = infile.read()
    infile.close()

    # 创建要转换成的html文件，文件名为：原始文件名后面加.html
    htmlfilename = mdfile + ".html"
    htmlfilePath = TEMP_ROOT_PATH + htmlfilename
    if os.path.exists(htmlfilePath):
        os.remove(htmlfilePath)
    outfile = open(htmlfilePath,'a')

    # 转换
    ret = markdown.markdown(md, extensions=exts)
    outfile.write(html % ret)
    outfile.close()

    return htmlfilename


def handler(event, context):
    srcBucket, srcObjName = getObsObjInfo4OBSTrigger(event)
    obs_address = context.getUserData('obs_address')
    outputBucket = context.getUserData('obs_output_bucket')    
    if obs_address is None:
        obs_address = '100.125.15.200'
    if outputBucket is None:
        outputBucket = 'casebucket-out'
        
    ak = context.getAccessKey()
    sk = context.getSecretKey()

    # download file uploaded by user from obs
    GetObject(obs_address, srcBucket, srcObjName, ak, sk)

    # 将markdown文件转换成html
    htmlfile = markdown2Html(srcObjName)

    # 将转换后的html文件上传到新的obs桶中
    PostObject (obs_address, outputBucket, htmlfile, ak, sk)

    return "OK"


if __name__ == '__main__':
    event = '{"record":[{"event_version":"1.0","smn":{"topic_urn":"urn:smn:southchina:66e0f4622d6f4e3fb2db2e495298a61a:swtest","timestamp":"2017-10-27T06:16:32Z","message_attributes":null,"message":"{\"Records\":[{\"eventVersion\":\"2.0\",\"eventSource\":\"aws:s3\",\"awsRegion\":\"southchina\",\"eventTime\":\"2017-10-27T06:16:29.950Z\",\"eventName\":\"ObjectCreated:Put\",\"userIdentity\":{\"principalId\":\"dc8c156df46d44ebbdefb43c37ae35a6\"},\"requestParameters\":{\"sourceIPAddress\":\"10.57.52.231\"},\"responseElements\":{\"x-amz-request-id\":\"0002F4BCF60000015F5C7989FE55F3C6\",\"x-amz-id-2\":\"DPq9pCp5+g6gkZtpd6EE2WiY4dsAObRPx9WuGfY4TNtGnFrtVblULW5QTJuD1Fyh\"},\"s3\":{\"s3SchemaVersion\":\"1.0\",\"configurationId\":\"swtest\",\"bucket\":{\"name\":\"swbucket\",\"ownerIdentity\":{\"PrincipalId\":\"39e798a6c701403ca78fd4c23b13e71a\"},\"arn\":\"arn:aws:s3:::swbucket\"},\"object\":{\"key\":\"favicon.ico\",\"eTag\":\"e3fde65d45896f909a4a2b3857328592\",\"size\":4286,\"versionId\":\"0000015F5C798A65ea5ec7bf799e61b67cb71e958eb78b53000355445346485a\",\"sequencer\":\"0000000015F5C798C1881FCC60000000\"}}}]}","type":"notification","message_id":"41ab709d3c7847e9bda8f1032d5777b2","subject":"OBS Notification"},"event_subscription_urn":"urn:fss:southchina:66e0f4622d6f4e3fb2db2e495298a61a:function:default:swtest:latest","event_source":"smn"}]}'
    handler(event, 0)
