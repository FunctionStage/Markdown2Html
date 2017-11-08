#!/usr/bin/python
# -*- coding:utf-8 -*-

import re
from com.obs.utils.request_format import RequestFormat,PathFormat,SubdomainFormat
from com.obs.models.base_model import LONG, IS_PYTHON2,UNICODE
from com.obs.log.log_client import INFO, WARNING, ERROR
from com.obs.log.Log import LOG
import hashlib
if IS_PYTHON2:
    import urllib
else:
    import urllib.parse as urllib
import base64
import hmac


METADATA_PREFIX = 'x-amz-meta-'
AMAZON_HEADER_PREFIX = 'x-amz-'
ALTERNATIVE_DATE_HEADER = 'x-amz-date'
GMT_DATE_FORMAT = '%a, %d %b %Y %H:%M:%S GMT'
LONG_DATE_FORMAT = '%Y%m%dT%H%M%SZ'
SHORT_DATE_FORMAT = '%Y%m%d'
EXPIRATION_DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

MIN_BUCKET_LENGTH = 3
MAX_BUCKET_LENGTH = 63

IPv4_REGEX = '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$'
BUCKET_NAME_REGEX = '^[a-z0-9]([a-z0-9\\-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9\\-]*[a-z0-9])?)*$'

SECURE_PORT = 443
INSECURE_PORT = 80

ALLOWED_RESOURCE_PARAMTER_NAMES = (
        'acl',
        'policy',
        'torrent',
        'logging',
        'location',
        'storageinfo',
        'quota',
        'storagepolicy',
        'requestpayment',
        'versions',
        'versioning',
        'versionid',
        'uploads',
        'uploadid',
        'partnumber',
        'website',
        'notification',
        'lifecycle',
        'deletebucket',
        'delete',
        'cors',
        'restore',
        'tagging',
        'response-content-type',
        'response-content-language',
        'response-expires',
        'response-cache-control',
        'response-content-disposition',
        'response-content-encoding')

ALLOWED_REQUEST_HTTP_HEADER_METADATA_NAMES = (
        'content-type',
        'content-md5',
        'content-length',
        'content-language',
        'expires',
        'origin',
        'cache-control',
        'content-disposition',
        'content-encoding',
        'access-control-request-method',
        'access-control-request-headers',
        'x-default-storage-class',
        'location',
        'date',
        'etag',
        'range',
        'host',
        'if-modified-since',
        'if-unmodified-since',
        'if-match',
        'if-none-match',
        'last-modified',
        'content-range')

ALLOWED_RESPONSE_HTTP_HEADER_METADATA_NAMES = (
        'content-type',
        'content-md5',
        'content-length',
        'content-language',
        'expires',
        'origin',
        'cache-control',
        'content-disposition',
        'content-encoding',
        'x-default-storage-class',
        'location',
        'date',
        'etag',
        'host',
        'last-modified',
        'content-range',
        'x-reserved',
        'access-control-allow-origin',
        'access-control-allow-headers',
        'access-control-max-age',
        'access-control-allow-methods',
        'access-control-expose-headers',
        'connection')


MIME_TYPES = {
    '7z': 'application/x-7z-compressed',
    'aac': 'audio/x-aac',
    'ai': 'application/postscript',
    'aif': 'audio/x-aiff',
    'asc': 'text/plain',
    'asf': 'video/x-ms-asf',
    'atom': 'application/atom+xml',
    'avi': 'video/x-msvideo',
    'bmp': 'image/bmp',
    'bz2': 'application/x-bzip2',
    'cer': 'application/pkix-cert',
    'crl': 'application/pkix-crl',
    'crt': 'application/x-x509-ca-cert',
    'css': 'text/css',
    'csv': 'text/csv',
    'cu': 'application/cu-seeme',
    'deb': 'application/x-debian-package',
    'doc': 'application/msword',
    'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'dvi': 'application/x-dvi',
    'eot': 'application/vnd.ms-fontobject',
    'eps': 'application/postscript',
    'epub': 'application/epub+zip',
    'etx': 'text/x-setext',
    'flac': 'audio/flac',
    'flv': 'video/x-flv',
    'gif': 'image/gif',
    'gz': 'application/gzip',
    'htm': 'text/html',
    'html': 'text/html',
    'ico': 'image/x-icon',
    'ics': 'text/calendar',
    'ini': 'text/plain',
    'iso': 'application/x-iso9660-image',
    'jar': 'application/java-archive',
    'jpe': 'image/jpeg',
    'jpeg': 'image/jpeg',
    'jpg': 'image/jpeg',
    'js': 'text/javascript',
    'json': 'application/json',
    'latex': 'application/x-latex',
    'log': 'text/plain',
    'm4a': 'audio/mp4',
    'm4v': 'video/mp4',
    'mid': 'audio/midi',
    'midi': 'audio/midi',
    'mov': 'video/quicktime',
    'mp3': 'audio/mpeg',
    'mp4': 'video/mp4',
    'mp4a': 'audio/mp4',
    'mp4v': 'video/mp4',
    'mpe': 'video/mpeg',
    'mpeg': 'video/mpeg',
    'mpg': 'video/mpeg',
    'mpg4': 'video/mp4',
    'oga': 'audio/ogg',
    'ogg': 'audio/ogg',
    'ogv': 'video/ogg',
    'ogx': 'application/ogg',
    'pbm': 'image/x-portable-bitmap',
    'pdf': 'application/pdf',
    'pgm': 'image/x-portable-graymap',
    'png': 'image/png',
    'pnm': 'image/x-portable-anymap',
    'ppm': 'image/x-portable-pixmap',
    'ppt': 'application/vnd.ms-powerpoint',
    'pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    'ps': 'application/postscript',
    'qt': 'video/quicktime',
    'rar': 'application/x-rar-compressed',
    'ras': 'image/x-cmu-raster',
    'rss': 'application/rss+xml',
    'rtf': 'application/rtf',
    'sgm': 'text/sgml',
    'sgml': 'text/sgml',
    'svg': 'image/svg+xml',
    'swf': 'application/x-shockwave-flash',
    'tar': 'application/x-tar',
    'tif': 'image/tiff',
    'tiff': 'image/tiff',
    'torrent': 'application/x-bittorrent',
    'ttf': 'application/x-font-ttf',
    'txt': 'text/plain',
    'wav': 'audio/x-wav',
    'webm': 'video/webm',
    'wma': 'audio/x-ms-wma',
    'wmv': 'video/x-ms-wmv',
    'woff': 'application/x-font-woff',
    'wsdl': 'application/wsdl+xml',
    'xbm': 'image/x-xbitmap',
    'xls': 'application/vnd.ms-excel',
    'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'xml': 'application/xml',
    'xpm': 'image/x-xpixmap',
    'xwd': 'image/x-xwindowdump',
    'yaml': 'text/yaml',
    'yml': 'text/yaml',
    'zip': 'application/zip'
}


def md5_encode(unencoded):
    m = hashlib.md5()
    unencoded = unencoded if IS_PYTHON2 else (unencoded.encode('UTF-8') if not isinstance(unencoded, bytes) else unencoded)
    m.update(unencoded)
    return m.digest()

def base64_encode(unencoded):
    unencoded = unencoded if IS_PYTHON2 else (unencoded.encode('UTF-8') if not isinstance(unencoded, bytes) else unencoded)
    encodeestr = base64.b64encode(unencoded, altchars=None)
    return encodeestr if IS_PYTHON2 else encodeestr.decode('UTF-8')

def validate_bucketname(bucket_name, calling_format):

    if isinstance(calling_format, PathFormat):
        flag = bucket_name and length_in_range(bucket_name, MIN_BUCKET_LENGTH, MAX_BUCKET_LENGTH) and \
               re.match(BUCKET_NAME_REGEX, bucket_name)  
        return flag
    return valid_subdomain_bucketname(bucket_name)

def encode_object_key(key):
    return encode_item(key, ',:?/=+&%')

def encode_item(item, safe):
    return urllib.quote(toString(item), safe)


def valid_subdomain_bucketname(bucket_name):

    return bucket_name \
            and length_in_range(bucket_name, MIN_BUCKET_LENGTH, MAX_BUCKET_LENGTH) \
            and not re.match(IPv4_REGEX, bucket_name) \
            and re.match(BUCKET_NAME_REGEX, bucket_name)


def safe_trans_to_utf8(item):
    if not IS_PYTHON2:
        return item
    if item is not None:
        item = safe_encode(item)
        try:
            return item.decode('GB2312').encode('UTF-8')
        except:
            return item

def safe_trans_to_gb2312(item):
    if not IS_PYTHON2:
        return item
    if item is not None:
        item = safe_encode(item)
        try:
            return item.decode('UTF-8').encode('GB2312')
        except:
            return item

def safe_encode(item):
    if not IS_PYTHON2:
        return item
    if isinstance(item, UNICODE):
        try:
            item = item.encode('UTF-8')
        except UnicodeDecodeError:
            try:
                item = item.encode('GB2312')
            except:
                item = None
    return item

def md5_file_encode_by_size_offset(file_path=None, size=None, offset=None, chuckSize=None):
    if file_path is not None and size is not None and offset is not None:
        m = hashlib.md5()
        with open(file_path, 'rb') as fp:
            CHUNKSIZE = 65536 if chuckSize is None else chuckSize
            fp.seek(offset)
            read_count = 0
            while read_count < size:
                read_size = CHUNKSIZE if size - read_count >= CHUNKSIZE else size - read_count
                data = fp.read(read_size)
                read_count_once = len(data)
                if read_count_once <= 0:
                    break
                m.update(data)
                read_count += read_count_once
        return m.digest()

def length_in_range(bucket_name, min_len, max_len):
    return len(bucket_name) >= min_len and len(bucket_name) <= max_len

def get_callingformat_for_bucket(desired_format, bucket_name):

    calling_format = desired_format
    if isinstance(calling_format, SubdomainFormat) and not valid_subdomain_bucketname(bucket_name):
        calling_format = RequestFormat.get_pathformat()

    return calling_format


def toBool(item):
    try:
        return True if item is not None and str(item).lower() == 'true' else False
    except Exception:
        return None

def toInt(item):
    try:
        return int(item)
    except Exception:
        return None

def toLong(item):
    try:
        return LONG(item)
    except Exception:
        return None

def toFloat(item):
    try:
        return float(item)
    except Exception:
        return None

def toString(item):
    try:
        return str(item) if item is not None else ''
    except Exception:
        return ''
    
def doClose(result, conn, connHolder):
    if not result:
        closeConn(conn, connHolder)
    elif 'close' == result.getheader('connection', '').lower() or 'close' == result.getheader('Connection', '').lower():
        LOG(INFO, 'server inform to close connection')
        closeConn(conn, connHolder)
    elif toInt(result.status) >= 500 or connHolder is None:
        closeConn(conn, connHolder)
    else:
        if connHolder is not None:
            connHolder['lock'].acquire()
            try:
                return connHolder['connSet'].add(conn)
            finally:
                connHolder['lock'].release()

def closeConn(conn, connHolder):
    try:
        if conn:
            conn.close()
    except Exception as ex:
        LOG(ERROR, ex)
    finally:
        if connHolder is not None:
            connHolder['lock'].acquire()
            try:
                connHolder['connSet'].remove(conn)
            except Exception as ex1:
                LOG(WARNING, ex1)
            finally:
                connHolder['lock'].release()
