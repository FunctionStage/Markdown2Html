#!/usr/bin/python
# -*- coding:utf-8 -*-

from com.obs.models.base_model import IS_PYTHON2

if IS_PYTHON2:
    import urllib
else:
    import urllib.parse as urllib

class RequestFormat(object):
    
    @staticmethod       
    def get_pathformat():
        return PathFormat()
    
    @staticmethod
    def get_subdomainformat():
        return SubdomainFormat()
    
    @staticmethod
    def get_vanityformat():
        return VanityFormat()

    @classmethod
    def convert_path_string(cls, path_args, allowdNames=None, safe=' ,:?&%'):
        e = ''
        if isinstance(path_args, dict):
            e1 = '?'
            e2 = '&'
            for path_key, path_value in path_args.items():
                flag = True
                if allowdNames is not None and path_key not in allowdNames:
                    flag = False
                if flag:
                    path_key = urllib.quote(str(path_key), safe)
                    if path_value is None:
                        e1 += path_key + '&'
                        continue
                    e2 += path_key + '=' + urllib.quote(str(path_value), safe) + '&'
            e = (e1 + e2).replace('&&', '&').replace('?&', '?')[:-1]
        return e

    @classmethod
    def toString(cls,item):
        try:
            return str(item) if item is not None else ''
        except:
            return ''

    @classmethod
    def encode_object_key(cls, key):
        return urllib.quote(cls.toString(key), ',:?/=+&%')

    def supports_locatedbuckets(self):
        '''
        '''
        return

    def get_endpoint(self, server, port, bucket):
        '''
        '''
        return
    
    def get_pathbase(self, bucket, key):
        '''
        '''
        return
    
    def get_url(self, bucket, key, path_args):
        '''
        '''
        return
    
class PathFormat(RequestFormat):
       
    def supports_locatedbuckets(self):
        return True 
    
    def get_server(self, server, bucket):
        return server
       
    def get_pathbase(self, bucket, key):
        if not bucket:
            return '/'
        if key is None:
            return '/' + bucket
        return '/' + bucket + '/' + self.encode_object_key(key)

    def get_endpoint(self, server, port, bucket):
        return server + ':' + str(port)

    def get_url(self, bucket, key, path_args):
        path_base = self.get_pathbase(bucket, key)
        path_arguments = self.convert_path_string(path_args)
        return path_base + path_arguments
    
    def get_full_url(self, is_secure, server, port, bucket, key, path_args):    
        url = 'https://' if is_secure else 'http://'
        url += self.get_endpoint(server, port, bucket)
        url += self.get_url(bucket, key, path_args)
        return url

class SubdomainFormat(RequestFormat):
       
    def supports_locatedbuckets(self):
        return True 

    def get_server(self, server, bucket):
        return bucket + '.' + server if bucket else server

    def get_pathbase(self, bucket, key):
        if key is None:
            return '/'
        return '/' + self.encode_object_key(key)

    def get_endpoint(self, server, port, bucket):
        return self.get_server(server, bucket) + ':' + str(port)
    
    def get_url(self, bucket, key, path_args):
        url = self.convert_path_string(path_args)
        return self.get_pathbase(bucket, key) + url if bucket else url

    def get_full_url(self, is_secure, server, port, bucket, key, path_args):
        url = 'https://' if is_secure else 'http://'
        url += self.get_endpoint(server, port, bucket)
        url += self.get_url(bucket, key, path_args)
        return url

   
           
class VanityFormat(SubdomainFormat):
           
    def get_server(self, server, bucket):
        return bucket

