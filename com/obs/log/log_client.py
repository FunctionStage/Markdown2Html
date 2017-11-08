#!/usr/bin/python  
# -*- coding:utf-8 -*- 

import logging
import logging.handlers
import os
import sys
import platform

_IS_WINDOWS = platform.system() == 'Windows' or os.name == 'nt'

_lock = None

if _IS_WINDOWS:
    import threading
    _lock = threading.Lock()
else:
    import multiprocessing
    _lock = multiprocessing.Lock()

_IS_PYTHON2 = sys.version_info.major == 2 or not sys.version > '3'

if _IS_PYTHON2:
    from ConfigParser import ConfigParser
else:
    from configparser import ConfigParser

_handler = logging.handlers.RotatingFileHandler

if not _IS_WINDOWS:
    try:
        from com.obs.log import cloghandler
        _handler = cloghandler.ConcurrentRotatingFileHandler
    except:
        pass

CRITICAL = logging.CRITICAL
ERROR = logging.ERROR
WARNING = logging.WARNING
INFO = logging.INFO
DEBUG = logging.DEBUG

LOG_LEVEL_DICT = {'CRITICAL':CRITICAL,'ERROR':ERROR,'WARNING':WARNING,'INFO':INFO,'DEBUG':DEBUG}

class LogConf(object):
    SEC = 'LOGCONF'
    def __init__(self, config_file=None, sec = SEC):
        if config_file:
            global LOG_LEVEL_DICT
            str_path = os.path.abspath(config_file)
            if not os.path.exists(str_path):
                raise Exception('%s is not exist' % (str_path))

            cf = ConfigParser()
            cf.read(config_file) if _IS_PYTHON2 else cf.read(config_file,'UTF-8')
            secs = cf.sections()
            if sec not in secs:
                raise Exception('%s is not in secs:%s' % (sec, str(secs)))

            items = cf.items(sec)
            idict = {}
            for e in items:
                idict[e[0]] = e[1]
            self.log_file_dir = idict.get('logfiledir', './')
            self.log_file_name = idict.get('logfilename', 'log.log')
            self.log_file_number = int(idict.get('logfilenumber', 0))
            self.log_file_size = int(idict.get('logfilesize', 0))
            self.print_log_to_console = int(idict.get('printlogtoconsole', 0))
            log_file_level = idict.get('logfilelevel')
            print_log_level = idict.get('printloglevel')
            self.log_file_level = LOG_LEVEL_DICT.get(log_file_level, DEBUG)
            self.print_log_level = LOG_LEVEL_DICT.get(print_log_level, DEBUG)
            self.disable = False
        else:
            self.disable = True

class NoneLogClient(object):
    def log(self, level, msg, *args, **kwargs):
        pass

    def LOG(self, level, msg, *args, **kwargs):
        pass

class LogClient(object):

    def __init__(self, log_config, log_name = 'OBS_LOGGER', display_name = None):
        if not log_config or not isinstance(log_config, LogConf):
            raise Exception('log config is not correct')
        self.log_config = log_config
        if display_name is None:
            display_name = log_name
        self.display_name = display_name
        self.logger = logging.getLogger(log_name)
        if not hasattr(self.logger, '_inited'):
            self.logger.setLevel(logging.DEBUG)
            if not log_config.disable:
                self.initLogger()
            self.logger._inited = 1

    def initLogger(self):
        if not os.path.exists(self.log_config.log_file_dir):
            global _lock
            _lock.acquire()
            try:
                if not os.path.exists(self.log_config.log_file_dir):
                    os.makedirs(self.log_config.log_file_dir, 0o755)
            finally:
                _lock.release()

        sep = '\\' if _IS_WINDOWS else '/'

        logfilepath = self.log_config.log_file_dir + sep + self.log_config.log_file_name

        encoding = None if _IS_PYTHON2 else 'UTF-8'
        formatter_handle = _handler(filename=logfilepath,encoding=encoding,
                                                                maxBytes=1024 * 1024 * self.log_config.log_file_size,
                                                                backupCount=self.log_config.log_file_number)
        formatter_handle.setLevel(self.log_config.log_file_level)
        formatter = logging.Formatter('%(asctime)s|process:%(process)d|thread:%(thread)d|%(levelname)s|HTTP(s)+XML|%(message)s|')
        formatter_handle.setFormatter(formatter)

        self.logger.addHandler(formatter_handle)
        if self.log_config.print_log_to_console == 1:
            console_handler = logging.StreamHandler()
            console_handler.setLevel(self.log_config.print_log_level)
            console_handler.setFormatter(formatter)

            self.logger.addHandler(console_handler)

    def log(self, level, msg, *args, **kwargs):
        self.LOG(level, msg, *args, **kwargs)

    def LOG(self, level, msg, *args, **kwargs):
        base_back = sys._getframe().f_back
        funcname = base_back.f_code.co_name
        while funcname.lower() == 'log':
            base_back = base_back.f_back
            funcname = base_back.f_code.co_name
        line = base_back.f_lineno
        msg = '%(logger)s|%(name)s,%(lineno)d|' % {'logger': self.display_name,'name': funcname, 'lineno': int(line)} + str(msg)

        if (level == CRITICAL):
            self.logger.critical(msg, *args, **kwargs)
        elif (level == ERROR):
            self.logger.error(msg, *args, **kwargs)
        elif (level == WARNING):
            self.logger.warning(msg, *args, **kwargs)
        elif (level == INFO):
            self.logger.info(msg, *args, **kwargs)
        elif (level == DEBUG):
            self.logger.debug(msg, *args, **kwargs)




