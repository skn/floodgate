# The contents of this file are subject to the BitTorrent Open Source License
# Version 1.1 (the License).  You may not copy or use this file, in either
# source code or executable form, except in compliance with the License.  You
# may obtain a copy of the License at http://www.bittorrent.com/license/.
#
# Software distributed under the License is distributed on an AS IS basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied.  See the License
# for the specific language governing rights and limitations under the
# License.

# Written by Bram Cohen and John Hoffman

import sys
import os
import signal
import re
import cPickle
import logging
import datetime
from urlparse import urlparse
from traceback import print_exc
from time import time, gmtime, strftime, localtime
from random import shuffle
from types import StringType, IntType, LongType, ListType, DictType
from binascii import b2a_hex
from cStringIO import StringIO

from BTL.translation import _

from BTL.obsoletepythonsupport import *

from BitTorrent import platform
from BTL import BTFailure
from BTL.platform import decode_from_filesystem, efs2
from BTL.defer import DeferredEvent, ThreadedDeferred
from BTL.yielddefer import wrap_task
from BitTorrent.configfile import parse_configuration_and_args
#from BitTorrent.parseargs import parseargs, printHelp
from BitTorrent.RawServer_twisted import RawServer
from BitTorrent.HTTPHandler import HTTPHandler
from BTL.parsedir import parsedir
from BitTorrent.NatCheck import NatCheck
from BTL.bencode import bencode, bdecode, Bencached
from urllib import quote, unquote
from BTL.exceptions import str_exc
from BitTorrent import version
from BitTorrent.prefs import Preferences
from BitTorrent.defaultargs import get_defaults
from BitTorrent.UI import Size
from BTL.hash import sha
from BitTorrent.PKTools import *


import socket
import threading
import traceback

NOISY = True

elogger = logging.getLogger('blub')
elogger.setLevel(logging.DEBUG)
 #create console handler and set level to debug
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
#create formatter
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
#add formatter to ch
ch.setFormatter(formatter)
#add ch to logger
elogger.addHandler(ch)


# code duplication because ow.
MAX_INCOMPLETE = 100
if os.name == 'nt':
    from BitTorrent.platform import win_version_num
    # starting in XP SP2 the incomplete outgoing connection limit was set to 10
    if win_version_num >= (2, 5, 1, 2, 0):
        MAX_INCOMPLETE = 10

def statefiletemplate(x):
    if type(x) != DictType:
        raise ValueError
    for cname, cinfo in x.iteritems():
        if cname == 'peers':
            for y in cinfo.itervalues():      # The 'peers' key is a dictionary of SHA hashes (torrent ids)
                 if type(y) != DictType:   # ... for the active torrents, and each is a dictionary
                     raise ValueError
                 for peerid, info in y.iteritems(): # ... of client ids interested in that torrent
                     if (len(peerid) != 20):
                         raise ValueError
                     if type(info) != DictType:  # ... each of which is also a dictionary
                         raise ValueError # ... which has an IP, a Port, and a Bytes Left count for that client for that torrent
                     if type(info.get('ip', '')) != StringType:
                         raise ValueError
                     port = info.get('port')
                     if type(port) not in (IntType, LongType) or port < 0:
                         raise ValueError
                     left = info.get('left')
                     if type(left) not in (IntType, LongType) or left < 0:
                         raise ValueError
        elif cname == 'completed':
            if (type(cinfo) != DictType): # The 'completed' key is a dictionary of SHA hashes (torrent ids)
                raise ValueError          # ... for keeping track of the total completions per torrent
            for y in cinfo.itervalues():      # ... each torrent has an integer value
                if type(y) not in (IntType,LongType):
                    raise ValueError      # ... for the number of reported completions for that torrent
        elif cname == 'allowed':
            if (type(cinfo) != DictType): # a list of info_hashes and included data
                raise ValueError
            if x.has_key('allowed_dir_files'):
                adlist = [z[1] for z in x['allowed_dir_files'].itervalues()]
                for y in cinfo.iterkeys():        # and each should have a corresponding key here
                    if not y in adlist:
                        raise ValueError
        elif cname == 'allowed_dir_files':
            if (type(cinfo) != DictType): # a list of files, their attributes and info hashes
                raise ValueError
            dirkeys = {}
            for y in cinfo.itervalues():      # each entry should have a corresponding info_hash
                if not y[1]:
                    continue
                if not x['allowed'].has_key(y[1]):
                    raise ValueError
                if dirkeys.has_key(y[1]): # and each should have a unique info_hash
                    raise ValueError
                dirkeys[y[1]] = 1


alas = _("your file may exist elsewhere in the universe\nbut alas, not here\n")

def isotime():
    #return strftime('%Y-%m-%d %H:%M UTC', gmtime(secs))
    return datetime.datetime.utcnow().isoformat()

http_via_filter = re.compile(' for ([0-9.]+)\Z')

def _get_forwarded_ip(headers):
    if headers.has_key('http_x_forwarded_for'):
        header = headers['http_x_forwarded_for']
        try:
            x,y = header.split(',')
        except:
            return header
        if not is_local_ip(x):
            return x
        return y
    if headers.has_key('http_client_ip'):
        return headers['http_client_ip']
    if headers.has_key('http_via'):
        x = http_via_filter.search(headers['http_via'])
        try:
            return x.group(1)
        except:
            pass
    if headers.has_key('http_from'):
        return headers['http_from']
    return None

def get_forwarded_ip(headers):
    x = _get_forwarded_ip(headers)
    if x is None or not is_valid_ipv4(x) or is_local_ip(x):
        return None
    return x

def compact_peer_info(ip, port):
    try:
        s = ( ''.join([chr(int(i)) for i in ip.split('.')])
              + chr((port & 0xFF00) >> 8) + chr(port & 0xFF) )
        if len(s) != 6:
            s = ''
    except:
        s = ''  # not a valid IP, must be a domain name
    return s

def is_valid_ipv4(ip):
    a = ip.split('.')
    if len(a) != 4:
        return False
    try:
        for x in a:
            chr(int(x))
        return True
    except:
        return False

def is_local_ip(ip):
    try:
        v = [int(x) for x in ip.split('.')]
        if v[0] == 10 or v[0] == 127 or v[:2] in ([192, 168], [169, 254]):
            return 1
        if v[0] == 172 and v[1] >= 16 and v[1] <= 31:
            return 1
    except ValueError:
        return 0

default_headers = {'Content-Type': 'text/plain', 'Pragma': 'no-cache'}

class Tracker(object):

    def __init__(self, config, rawserver):
        
        
        #add ch to logger
        elogger.addHandler(ch)
        elogger.debug("debug message")
        elogger.info("info message")
        elogger.warn("warn message")
        elogger.error("error message")
        elogger.critical("critical message")
        
        
        self.config = config
        self.response_size = config['response_size']
        self.max_give = config['max_give']
        self.dfile = efs2(config['dfile'])
        self.natcheck = config['nat_check']
        favicon = config['favicon']
        self.favicon = None
        if favicon:
            try:
                h = open(favicon,'r')
                self.favicon = h.read()
                h.close()
            except:
                errorfunc(logging.WARNING,
                          _("specified favicon file -- %s -- does not exist.") %
                          favicon)
        self.rawserver = rawserver
        self.cached = {}    # format: infohash: [[time1, l1, s1], [time2, l2, s2], [time3, l3, s3]]
        self.cached_t = {}  # format: infohash: [time, cache]
        self.times = {}
        self.state = {}
        self.seedcount = {}
        self.save_pending = False
        self.parse_pending = False
        
        #EZ
        self.micropaid_downloads ={} #contains key=infohash value=dict[peerid]=payment_keys 
        self.metainfos = {} #contains metainfo dictionaries  with the infohash as key
        self.peer_certificates_by_peer_id = {} # these can only be filled in when requests containing peerid and cn's are coming in
        self.peer_certificates_by_cn = {}
        
        certificate_dir = config['micropayment_peer_certificates_dir']
        ca_dir = self.config["micropayment_trusted_ca_dir"]
        self.pk_tools = None
        if ca_dir:
            print "ca dir not none:  %s" % ca_dir
            elogger.debug( "logger ca dir not none:  %s" % ca_dir)
           
            self.pk_tools = PKTools(ca_dir)
            if certificate_dir:
                self.peer_certificates_by_cn = self.update_peer_certificates(self.peer_certificates_by_cn,certificate_dir)
            if config['micropayment_private_key'] is not None:
                private_key_file = open(config['micropayment_private_key'])
                self.private_key = parse_PEM_private_key(private_key_file)
        else:
            print "no cadir found"
            self.ezdebug("no cadir found");

        self.only_local_override_ip = config['only_local_override_ip']
        if self.only_local_override_ip == 2:
            self.only_local_override_ip = not config['nat_check']

        if os.path.exists(self.dfile):
            try:
                h = open(self.dfile, 'rb')
                ds = h.read()
                h.close()
                try:
                    tempstate = cPickle.loads(ds)
                except:
                    tempstate = bdecode(ds)  # backwards-compatibility.
                if not tempstate.has_key('peers'):
                    tempstate = {'peers': tempstate}
                statefiletemplate(tempstate)
                self.state = tempstate
            except:
                errorfunc(logging.WARNING,
                          _("statefile %s corrupt; resetting") % self.dfile)

        self.downloads = self.state.setdefault('peers', {})
        self.completed = self.state.setdefault('completed', {})

        self.becache = {}   # format: infohash: [[l1, s1], [l2, s2], [l3, s3]]
        for infohash, ds in self.downloads.iteritems():
            self.seedcount[infohash] = 0
            for x, y in ds.iteritems():
                if not y.get('nat', -1):
                    ip = y.get('given_ip')
                    if not (ip and self.allow_local_override(y['ip'], ip)):
                        ip = y['ip']
                    self.natcheckOK(infohash, x, ip, y['port'], y['left'])
                if not y['left']:
                    self.seedcount[infohash] += 1

        for infohash in self.downloads:
            self.times[infohash] = {}
            for peerid in self.downloads[infohash]:
                self.times[infohash][peerid] = 0

        self.reannounce_interval = config['reannounce_interval']
        self.save_dfile_interval = config['save_dfile_interval']
        self.show_names = config['show_names']
        rawserver.add_task(self.save_dfile_interval, self.save_dfile)
        self.prevtime = time()
        self.timeout_downloaders_interval = config['timeout_downloaders_interval']
        rawserver.add_task(self.timeout_downloaders_interval, self.expire_downloaders)
        self.logfile = None
        self.log = None
        if (config['logfile'] != '') and (config['logfile'] != '-'):
            try:
                self.logfile = config['logfile']
                self.log = open(self.logfile, 'a')
                sys.stdout = self.log
                print _("# Log Started: "), isotime()
            except:
                 print _("**warning** could not redirect stdout to log file: "), sys.exc_info()[0]

        if config['hupmonitor']:
            def huphandler(signum, frame, self = self):
                try:
                    self.log.close ()
                    self.log = open(self.logfile, 'a')
                    sys.stdout = self.log
                    print _("# Log reopened: "), isotime()
                except:
                    print _("***warning*** could not reopen logfile")

            signal.signal(signal.SIGHUP, huphandler)

        self.allow_get = config['allow_get']

        if config['allowed_dir'] != '':
            self.allowed_dir = config['allowed_dir']
            self.parse_dir_interval = config['parse_dir_interval']
            self.allowed = self.state.setdefault('allowed', {})
            self.allowed_dir_files = self.state.setdefault('allowed_dir_files', {})
            self.allowed_dir_blocked = {}
            self.parse_allowed()
        else:
            try:
                del self.state['allowed']
            except:
                pass
            try:
                del self.state['allowed_dir_files']
            except:
                pass
            self.allowed = None

        self.uq_broken = unquote('+') != ' '
        self.keep_dead = config['keep_dead']

    def allow_local_override(self, ip, given_ip):
        return is_valid_ipv4(given_ip) and (
            not self.only_local_override_ip or is_local_ip(ip) )

    def get_infopage(self):
        try:
            if not self.config['show_infopage']:
                return (404, 'Not Found', default_headers, alas)
            red = self.config['infopage_redirect']
            if red != '':
                return (302, 'Found', {'Content-Type': 'text/html', 'Location': red},
                        '<A HREF="'+red+'">Click Here</A>')

            s = StringIO()
            s.write('<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.1//EN" "http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd">\n' \
                '<html><head><title>BitTorrent download info</title>\n')
            if self.favicon is not None:
                s.write('<link rel="shortcut icon" href="/favicon.ico">\n')
            s.write('</head>\n<body>\n' \
                '<h3>BitTorrent download info</h3>\n'\
                '<ul>\n'
                '<li><strong>tracker version:</strong> %s</li>\n' \
                '<li><strong>server time:</strong> %s</li>\n' \
                '</ul>\n' % (version, isotime()))
            if self.allowed is not None:
                if self.show_names:
                    names = [ (value[1].name, infohash)
                              for infohash, value in self.allowed.iteritems()]
                else:
                    names = [(None, infohash) for infohash in self.allowed]
            else:
                names = [ (None, infohash) for infohash in self.downloads]
            if not names:
                s.write('<p>not tracking any files yet...</p>\n')
            else:
                names.sort()
                tn = 0
                tc = 0
                td = 0
                tt = 0  # Total transferred
                ts = 0  # Total size
                nf = 0  # Number of files displayed
                if self.allowed is not None and self.show_names:
                    s.write('<table summary="files" border="1">\n' \
                        '<tr><th>info hash</th><th>torrent name</th><th align="right">size</th><th align="right">complete</th><th align="right">downloading</th><th align="right">downloaded</th><th align="right">transferred</th></tr>\n')
                else:
                    s.write('<table summary="files">\n' \
                        '<tr><th>info hash</th><th align="right">complete</th><th align="right">downloading</th><th align="right">downloaded</th></tr>\n')
                for name, infohash in names:
                    l = self.downloads[infohash]
                    n = self.completed.get(infohash, 0)
                    tn = tn + n
                    c = self.seedcount[infohash]
                    tc = tc + c
                    d = len(l) - c
                    td = td + d
                    nf = nf + 1
                    if self.allowed is not None and self.show_names:
                        if self.allowed.has_key(infohash):
                            sz = self.allowed[infohash]['length']  # size
                            ts = ts + sz
                            szt = sz * n   # Transferred for this torrent
                            tt = tt + szt
                            if self.allow_get == 1:
                                linkname = '<a href="/file?info_hash=' + quote(infohash) + '">' + name + '</a>'
                            else:
                                linkname = name
                            s.write('<tr><td><code>%s</code></td><td>%s</td><td align="right">%s</td><td align="right">%i</td><td align="right">%i</td><td align="right">%i</td><td align="right">%s</td></tr>\n' \
                                % (b2a_hex(infohash), linkname, size_format(sz), c, d, n, size_format(szt)))
                    else:
                        s.write('<tr><td><code>%s</code></td><td align="right"><code>%i</code></td><td align="right"><code>%i</code></td><td align="right"><code>%i</code></td></tr>\n' \
                            % (b2a_hex(infohash), c, d, n))
                ttn = 0
                for i in self.completed.itervalues():
                    ttn = ttn + i
                if self.allowed is not None and self.show_names:
                    s.write('<tr><td align="right" colspan="2">%i files</td><td align="right">%s</td><td align="right">%i</td><td align="right">%i</td><td align="right">%i/%i</td><td align="right">%s</td></tr>\n'
                            % (nf, size_format(ts), tc, td, tn, ttn, size_format(tt)))
                else:
                    s.write('<tr><td align="right">%i files</td><td align="right">%i</td><td align="right">%i</td><td align="right">%i/%i</td></tr>\n'
                            % (nf, tc, td, tn, ttn))
                s.write('</table>\n' \
                    '<ul>\n' \
                    '<li><em>info hash:</em> SHA1 hash of the "info" section of the metainfo (*.torrent)</li>\n' \
                    '<li><em>complete:</em> number of connected clients with the complete file</li>\n' \
                    '<li><em>downloading:</em> number of connected clients still downloading</li>\n' \
                    '<li><em>downloaded:</em> reported complete downloads (total: current/all)</li>\n' \
                    '<li><em>transferred:</em> torrent size * total downloaded (does not include partial transfers)</li>\n' \
                    '</ul>\n')

            s.write('</body>\n' \
                '</html>\n')
            return (200, 'OK',
                    {'Content-Type': 'text/html; charset=iso-8859-1'},
                    s.getvalue())
        except:
            print_exc()
            return (500, 'Internal Server Error',
                    {'Content-Type': 'text/html; charset=iso-8859-1'},
                    'Server Error')

    def scrapedata(self, infohash, return_name = True):
        l = self.downloads[infohash]
        n = self.completed.get(infohash, 0)
        c = self.seedcount[infohash]
        d = len(l) - c
        f = {'complete': c, 'incomplete': d, 'downloaded': n}
        if return_name and self.show_names and self.allowed is not None:
            f['name'] = self.allowed[infohash]['name']
        return (f)

    def get_scrape(self, paramslist):
        fs = {}

        if paramslist.has_key('info_hash'):
            if self.config['scrape_allowed'] not in ['specific', 'full']:
                return (400, 'Not Authorized', default_headers,
                    bencode({'failure_reason':
                    "specific scrape function is not available with this tracker."}))
            for infohash in paramslist['info_hash']:
                if self.allowed is not None and infohash not in self.allowed:
                    continue
                if infohash in self.downloads:
                    fs[infohash] = self.scrapedata(infohash)
        else:
            if self.config['scrape_allowed'] != 'full':
                return (400, 'Not Authorized', default_headers,
                    bencode({'failure reason':
                    "full scrape function is not available with this tracker."}))
                    #bencode({'failure reason':
                    #_("full scrape function is not available with this tracker.")}))
            if self.allowed is not None:
                hashes = self.allowed
            else:
                hashes = self.downloads
            for infohash in hashes:
                fs[infohash] = self.scrapedata(infohash)

        return (200, 'OK', {'Content-Type': 'text/plain'}, bencode({'files': fs}))

    def get_file(self, infohash):
         if not self.allow_get:
             return (400, 'Not Authorized',
                     default_headers,
                 _("get function is not available with this tracker."))
         if not self.allowed.has_key(infohash):
             return (404, 'Not Found', default_headers, alas)
         fname = self.allowed[infohash]['file']
         fpath = self.allowed[infohash]['path']
         return (200, 'OK', {'Content-Type': 'application/x-bittorrent',
             'Content-Disposition': 'attachment; filename=' + fname},
             open(fpath, 'rb').read())

    def check_allowed(self, infohash, paramslist):
        if self.allowed is not None:
            if not self.allowed.has_key(infohash):
                return (200, 'Not Authorized', default_headers,
                    bencode({'failure reason':
                    "Requested download is not authorized for use with this tracker."}))
                    #_("Requested download is not authorized for use with this tracker.")}))
            if self.config['allowed_controls']:
                if self.allowed[infohash].has_key('failure reason'):
                    return (200, 'Not Authorized', default_headers,
                        bencode({'failure reason': self.allowed[infohash]['failure reason']}))

        return None

    def add_data(self, infohash, event, ip, paramslist):
        peers = self.downloads.setdefault(infohash, {})
        ts = self.times.setdefault(infohash, {})
        self.completed.setdefault(infohash, 0)
        self.seedcount.setdefault(infohash, 0)

        self._print_event("entered add data")

        def params(key, default = None, l = paramslist):
            if l.has_key(key):
                return l[key][0]
            return default

        myid = params('peer_id','')
        if len(myid) != 20:
            raise ValueError, 'id not of length 20'
        if event not in ['started', 'completed', 'stopped', 'snooped', None]:
            raise ValueError, 'invalid event'
        port = int(params('port',''))
        if port < 0 or port > 65535:
            raise ValueError, 'invalid port'
        left = int(params('left',''))
        if left < 0:
            raise ValueError, 'invalid amount left'

        peer = peers.get(myid)
        mykey = params('key')
        auth = not peer or peer.get('key', -1) == mykey or peer.get('ip') == ip

        gip = params('ip')
        local_override = gip and self.allow_local_override(ip, gip)
        if local_override:
            ip1 = gip
        else:
            ip1 = ip
        if not auth and local_override and self.only_local_override_ip:
            auth = True

        if params('numwant') is not None:
            rsize = min(int(params('numwant')), self.max_give)
        else:
            rsize = self.response_size

        if event == 'stopped':
            if peer and auth:
                self.delete_peer(infohash,myid)


        
        elif not peer:
            self._print_event("entered not peer block in add data")
            ts[myid] = time()
            peer = {'ip': ip, 'port': port, 'left': left}
            
            if mykey:
                peer['key'] = mykey
            if gip:
                peer['given ip'] = gip
            if port:
                if not self.natcheck or (local_override and self.only_local_override_ip):
                    peer['nat'] = 0
                    self.natcheckOK(infohash,myid,ip1,port,left)
                else:
                    NatCheck(self.connectback_result,infohash,myid,ip1,port,self.rawserver)
            else:
                peer['nat'] = 2**30
            if event == 'completed':
                self.completed[infohash] += 1
            if not left:
                self.seedcount[infohash] += 1
            peers[myid] = peer
            
            

        else:
            if not auth:
                return rsize    # return w/o changing stats

            ts[myid] = time()
            if not left and peer['left']:
                self.completed[infohash] += 1
                self.seedcount[infohash] += 1
                if not peer.get('nat', -1):
                    for bc in self.becache[infohash]:
                        bc[1][myid] = bc[0][myid]
                        del bc[0][myid]
            if peer['left']:
                peer['left'] = left

            recheck = False
            if ip != peer['ip']:
                peer['ip'] = ip
                recheck = True
            if gip != peer.get('given ip'):
                if gip:
                    peer['given ip'] = gip
                elif peer.has_key('given ip'):
                    del peer['given ip']
                if local_override:
                    if self.only_local_override_ip:
                        self.natcheckOK(infohash,myid,ip1,port,left)
                    else:
                        recheck = True

            if port and self.natcheck:
                if recheck:
                    if peer.has_key('nat'):
                        if not peer['nat']:
                            l = self.becache[infohash]
                            y = not peer['left']
                            for x in l:
                                del x[y][myid]
                        del peer['nat'] # restart NAT testing
                else:
                    natted = peer.get('nat', -1)
                    if natted and natted < self.natcheck:
                        recheck = True

                if recheck:
                    NatCheck(self.connectback_result,infohash,myid,ip1,port,self.rawserver)
        
                self._print_event("about to return form add data");
        return rsize

    def peerlist(self, infohash, stopped, is_seed, return_type, rsize):
        print "in peerlist"
        data = {}    # return data
        seeds = self.seedcount[infohash]
        data['complete'] = seeds
        data['incomplete'] = len(self.downloads[infohash]) - seeds

        if ( self.allowed is not None and self.config['allowed_controls'] and
                                self.allowed[infohash].has_key('warning message') ):
            data['warning message'] = self.allowed[infohash]['warning message']

        data['interval'] = self.reannounce_interval
        if stopped or not rsize:     # save some bandwidth
            print "peer is stopped or rsize=0"
            data['peers'] = []
            return data

        bc = self.becache.setdefault(infohash,[[{}, {}], [{}, {}], [{}, {}]])
        len_l = len(bc[0][0]) #length of leechers?
        len_s = len(bc[0][1]) #length of seeders?
        if not (len_l+len_s):   # caches are empty!
            print "caches are empty"
            data['peers'] = []
            return data
        l_get_size = int(float(rsize)*(len_l)/(len_l+len_s))
        cache = self.cached.setdefault(infohash,[None,None,None])[return_type]
        if cache:
            if cache[0] + self.config['min_time_between_cache_refreshes'] < time(): #still to soon to refresh cache
                cache = None
            else:
                if ( (is_seed and len(cache[1]) < rsize)
                     or len(cache[1]) < l_get_size or not cache[1] ):
                        cache = None
        if not cache:
            vv = [[],[],[]]
            cache = [ time(),
                      bc[return_type][0].values()+vv[return_type],
                      bc[return_type][1].values() ]
            shuffle(cache[1])
            shuffle(cache[2])
            self.cached[infohash][return_type] = cache
            for rr in xrange(len(self.cached[infohash])):
                if rr != return_type:
                    try:
                        self.cached[infohash][rr][1].extend(vv[rr])
                    except:
                        pass
        if len(cache[1]) < l_get_size:
            print "setting peerdate to cache 1"
            peerdata = cache[1]
            if not is_seed:
                peerdata.extend(cache[2])
            cache[1] = []
            cache[2] = []
        else:
            print "about to do new peerlist part"
            if not is_seed:
                print "not seed size of cache 2 is %d",len(cache[2])
                #peerdata = cache[2]
                peerdata = cache[2][l_get_size-rsize:]
                del cache[2][l_get_size-rsize:] # a try to distribute peerlist containing more seeders (by commenting this line out(
                rsize -= len(peerdata)
            else:
                peerdata = []
            if rsize:
                print "still space in request to fill with peers, size of cache 1 is %d",len(cache[1])
                #peerdata.extend(cache[1])
                peerdata.extend(cache[1][-rsize:])
                del cache[1][-rsize:]      # a try to distribute peerlist containing more seeders (by commenting this line out(
            print "peerdata is %s" % str(peerdata)
        if return_type == 2:
            print "peerdata is %s" % str(peerdata)
            peerdata = ''.join(peerdata)
        data['peers'] = peerdata
        
        return data

    def get(self, connection, path, headers):
        send_payment_keys = False
        generated_payment_keys = None
        ip = connection.get_ip()

        nip = get_forwarded_ip(headers)
        if nip and not self.only_local_override_ip:
            ip = nip

        paramslist = {}
        def params(key, default = None, l = paramslist):
            if l.has_key(key):
                return l[key][0]
            return default
        self._print_event("urlstring="+path)

        try:
            (scheme, netloc, path, pars, query, fragment) = urlparse(path)
            print("path rcvd = %s" % path)
            self._print_event("after passing path");
            if self.uq_broken == 1:
                path = path.replace('+',' ')
                query = query.replace('+',' ')
            path = unquote(path)[1:]
            self._print_event("after passing path2 %s" % path);
            for s in query.split('&'):
                if s != '':
                    i = s.index('=')
                    kw = unquote(s[:i])
                    paramslist.setdefault(kw, [])
                    paramslist[kw] += [unquote(s[i+1:])]
            self._print_event("after passing path3");
            if path == '' or path == 'index.html':
                return self.get_infopage()
            if path == 'scrape':
                return self.get_scrape(paramslist)
            if (path == 'file'):
                return self.get_file(params('info_hash'))
            if path == 'favicon.ico' and self.favicon is not None:
                return (200, 'OK', {'Content-Type' : 'image/x-icon'}, self.favicon)
            if path != 'announce':
                return (404, 'Not Found', default_headers, alas)

            # main tracker function
            infohash = params('info_hash')
            if not infohash:
                raise ValueError, 'no info hash'

            notallowed = self.check_allowed(infohash, paramslist)
            if notallowed:
                if NOISY:
                    self._print_event( "get: NOT ALLOWED: info_hash=%s, %s" %
                                       (infohash.encode('hex'). str(notallowed)) )
                return notallowed
            
            peerid = params('peer_id')
            if self.metainfos[infohash].micropayments == True: 
                print "micropaid"
                if self.downloads[infohash] is not None: 
                    print "download exists"
                    if peerid not in self.downloads[infohash]:
                        print "keys of dl[ihash] " +str(self.downloads[infohash].keys())
                        print "own peerid: "+peerid
                        send_payment_keys = True
                        self._print_event("calling generate payment keys");
                        generated_payment_keys = self.generate_payment_keys(infohash,peerid)
                        self._print_event("after generate payment keys");
                    else:
                        print "peerid already in downloader list"
                else:
                    print "infohash not in downloads"
            else:
                 print "NO key generation needed" 


            event = params('event')
            self._print_event("event type=%s" % event);
            self._print_event("befor add data");
            rsize = self.add_data(infohash, event, ip, paramslist)
            self._print_event("after add data");

        except ValueError, e:
            print e
            if NOISY:
                self._print_exc( "get: ",e )
            return (401, 'Bad Request',
                    {'Content-Type': 'text/plain'},
                    'you sent me garbage - ' + str_exc(e))
        

        if params('compact'):
            return_type = 2
        elif params('no_peer_id'):
            return_type = 1
        else:
            return_type = 0

        print "calling self.peerlist"
        data = self.peerlist(infohash, event=='stopped', not params('left'),
                             return_type, rsize)
       
       
       
        
        
        
        
        
          
        if send_payment_keys:
            if(peerid == None):
                return (402, 'Bad Request',
                    {'Content-Type': 'text/plain'},
                    'peer id is required for micropayments' )
            if(params('cn') == None):
                return (403, 'Bad Request',
                    {'Content-Type': 'text/plain'},
                    'cn is required for micropayments' )
                    
            #append payment keys
            sig = params('sig')
            print "received cn=%s" % params('cn')
            peer_cert = self.peer_certificates_by_cn[params('cn')]
            peer_pubkey = peer_cert.publicKey
            peer_id = params('peer_id')
            sig_ok = self.check_signature_of_query(sig,query,peer_cert)
            if sig_ok:
                self.peer_certificates_by_peer_id[peer_id] = peer_cert
            else:
                 print "sig not ok for at send payment keys"
                 return (404, 'Bad Request',
                    {'Content-Type': 'text/plain'},
                    'bad signature' )
            print "infohash in send payments =>%s<=,  " %  infohash.encode('hex') 
            print "hex peer id is %s" % params('peer_id').encode('hex')
            mp_keys_of_torrent = self.micropaid_downloads[infohash]
            print "mp keys of torrent %d" % len(mp_keys_of_torrent)
            data['keylist'] = "".join(mp_keys_of_torrent[params('peer_id')])
            data['keylist'] = self.pk_tools.encrypt_piece_tls(peer_pubkey, data['keylist']).encode('hex')
            data['sig'] = self.pk_tools.get_sha_signature_tls(self.private_key, data['keylist']).encode('hex') #signature over the keylist
            print "signature=%s" % data['sig']
            print("added keylist to tracker reply reply len = %d: " % len(data['keylist']))
        
        
        if(params('requestkeyhashlist')):
             peer_id = params('peer_id')
             if(peer_id == None):
                return (405, 'Bad Request',
                    {'Content-Type': 'text/plain'},
                    'peer id is required for micropayments' )
             
             sig = params('sig')
             peer_cert = self.peer_certificates_by_peer_id[peer_id]
             sig_ok = self.check_signature_of_query(sig,query,peer_cert)
             if not sig_ok:
                 return (406, 'Bad Request',
                    {'Content-Type': 'text/plain'},
                    'bad signature' )
             
             
             print "hex peer id is %s" % params('peer_id').encode('hex')
             #todo hash these keys
             mp_keys_of_torrent = self.micropaid_downloads[infohash]
             print "peerids in torrent are: "
             
             #todo: include peerid so we can send multiple keyhashlist at the same time
             #todo: do plain instead of hexdigest in get_paymentkeyshashlist
             data['keyhashlist'] = self.get_payment_key_hash_list(infohash,params('requestkeyhashlist'))
             data['keyhashlist'] = self.pk_tools.encrypt_piece_tls(peer_cert.publicKey,data['keyhashlist']).encode("hex")
             data['sig'] = self.pk_tools.get_sha_signature_tls(self.private_key, data['keyhashlist']).encode('hex') #signature over hex encoded keyhashlist
             print "hashed keys: " + quote(data['keyhashlist'])
             #data['keyhashlist'] = "".join(mp_keys_of_torrent[params('requestkeyhashlist')])
             print "added keys to request"
             
      

        if paramslist.has_key('scrape'):
            data['scrape'] = self.scrapedata(infohash, False)
        
        rotzooi = ''
        for num in range(1,200): rotzooi+= "%03d" % num
       
        #weird twisted.partialDownloadError at client side disappears when we add junk to the response...
        data['rotzooi'] = rotzooi 
        bencoded_data = bencode(data)
        print "length of data in track.py: %d" % len(bencoded_data)
        
        return (200, 'OK', default_headers,bencode(data) )

    def natcheckOK(self, infohash, peerid, ip, port, not_seed):
        bc = self.becache.setdefault(infohash,[[{}, {}], [{}, {}], [{}, {}]])
        bc[0][not not_seed][peerid] = Bencached(bencode({'ip': ip, 'port': port,
                                              'peer id': peerid}))
        bc[1][not not_seed][peerid] = Bencached(bencode({'ip': ip, 'port': port}))
        bc[2][not not_seed][peerid] = compact_peer_info(ip, port)

    def natchecklog(self, peerid, ip, port, result):
        print isotime(), '"!natcheck-%s:%i" %s %i 0 - -' % (
            ip, quote(peerid), port, result)

    def connectback_result(self, result, downloadid, peerid, ip, port):
        record = self.downloads.get(downloadid, {}).get(peerid)
        if ( record is None
                 or (record['ip'] != ip and record.get('given ip') != ip)
                 or record['port'] != port ):
            if self.config['log_nat_checks']:
                self.natchecklog(peerid, ip, port, 404)
            return
        if self.config['log_nat_checks']:
            if result:
                x = 200
            else:
                x = 503
            self.natchecklog(peerid, ip, port, x)
        if not record.has_key('nat'):
            record['nat'] = int(not result)
            if result:
                self.natcheckOK(downloadid,peerid,ip,port,record['left'])
        elif result and record['nat']:
            record['nat'] = 0
            self.natcheckOK(downloadid,peerid,ip,port,record['left'])
        elif not result:
            record['nat'] += 1

    def save_dfile(self):
        if self.save_pending:
            return
        self.save_pending = True

        # if this is taking all the time, threading it won't help anyway because
        # of the GIL
        #state = bencode(self.state)
        state = cPickle.dumps(self.state) # pickle handles Unicode.

        df = ThreadedDeferred(wrap_task(self.rawserver.external_add_task),
                              self._save_dfile, state)
        def cb(r):
            self.save_pending = False
            if NOISY:
                self._print_event( "save_dfile: Completed" )
        def eb(etup):
            self.save_pending = False
            self._print_exc( "save_dfile: ", etup )
        df.addCallbacks(cb, eb)

    def _save_dfile(self, state):
        exc_info = None
        try:
            h = open(self.dfile, 'wb')
            h.write(state)
            h.close()
        except:
            exc_info = sys.exc_info()
        self.rawserver.external_add_task(self.save_dfile_interval, self.save_dfile)
        if exc_info:
            raise exc_info[0], exc_info[1], exc_info[2]

    def parse_allowed(self):
        if self.parse_pending:
            return
        self.parse_pending = True

        df = ThreadedDeferred(wrap_task(self.rawserver.external_add_task),
                              self._parse_allowed, daemon=True)
        def eb(etup):
            self.parse_pending = False
            self._print_exc("parse_dir: ", etup)
        df.addCallbacks(self._parse_allowed_finished, eb)

    def _parse_allowed(self):
        def errfunc(message, exc_info=None):
            # logging broken .torrent files would be useful but could confuse
            # programs parsing log files
            m = "parse_dir: %s" % message
            if exc_info:
                self._print_exc(m, exc_info)
            else:
                self._print_event(m)
            pass
        r = parsedir(self.allowed_dir, self.allowed, self.allowed_dir_files,
                     self.allowed_dir_blocked, errfunc, include_metainfo = False)

        # register the call to parse a dir.
        self.rawserver.external_add_task(self.parse_dir_interval,
                                         self.parse_allowed)

        return r

    def _parse_allowed_finished(self, r):
        self.parse_pending = False
        ( self.allowed, self.allowed_dir_files, self.allowed_dir_blocked,
          added, removed ) = r
        if NOISY:
            self._print_event("_parse_allowed_finished: removals: %s" %
                              str(removed))

        for infohash in added.keys():
            
            
            #EZ store metainfo files in memory because they are needed for key genereation:
            #EZ the amount of pieces determines the amount of payment_keys needed
            #EZ normally the tracker is agnostic of the pieces
            #TODO maybe make it more efficient later, all the piece hashes from metainfo arent needed
            (path,metainfo) = added[infohash]
            self._print_event("===============infohash in track.py after parsedir path= announce from metainfo %s" % path )
            #if type(metainfo) != DictType:
            #    self._print_event("wrong type metainfo: %s" % type(metainfo))
            #    raise ValueError
            #it is a convertedMetaInfo type
            self.metainfos[infohash] = metainfo
            self.downloads.setdefault(infohash, {})
            self.completed.setdefault(infohash, 0)
            self.seedcount.setdefault(infohash, 0)

        self.state['allowed'] = self.allowed
        self.state['allowed_dir_files'] = self.allowed_dir_files

    def delete_peer(self, infohash, peerid):
        dls = self.downloads[infohash]
        peer = dls[peerid]
        if not peer['left']:
            self.seedcount[infohash] -= 1
        if not peer.get('nat', -1):
            l = self.becache[infohash]
            y = not peer['left']
            for x in l:
                del x[y][peerid]
        del self.times[infohash][peerid]
        del dls[peerid]

    def expire_downloaders(self):
        for infohash, peertimes in self.times.iteritems():
            items = peertimes.items()
            for myid, t in items:
                if t < self.prevtime:
                    self.delete_peer(infohash, myid)
        self.prevtime = time()
        if self.keep_dead != 1:
            items = self.downloads.items()
            for key, peers in items:
                if len(peers) == 0 and (self.allowed is None or
                                        key not in self.allowed):
                    del self.times[key]
                    del self.downloads[key]
                    del self.seedcount[key]
        self.rawserver.add_task(self.timeout_downloaders_interval,
                                self.expire_downloaders)

    def _print_event(self, message):
        print datetime.datetime.utcnow().isoformat(), message

    def _print_exc(self, note, etup):
        print datetime.datetime.utcnow().isoformat(), note, ':'
        traceback.print_exception(*etup)


    #ez
    def generate_payment_keys(self,infohash,myid):
        
        
        print "type of infohash %s" % (str(type(infohash)))
        if type(infohash) != str:
            raise TypeError
        print("generating payment keys for myid")
        if self.metainfos == None:
            print("generate payment keys: metainfos== None")
            return False
        print("generate payment keys: metainfos != None "+str(self.metainfos))
        for ihash in self.metainfos.keys():
            match = ihash == infohash
            print "found key  comparing to arg , result: %d, type ihash=%s" % (match, str(type(ihash)) )
            last_key = ihash
    
            
            
        if infohash not in self.metainfos.keys():
            print("generate payment keys: metainfos[infohash] not found ")
            return False
        else: 
            print "infohash in dict"
            
        if not self.metainfos[infohash].micropayments:
            print "this torrent is not micropaid"
            return False
        else: 
            print "this torrent is micropaid"
        #print("generate payment keys:metainfos[infohash]  found")
        #if not self.metainfos[infohash]['micropayments']:
        #    print("generate payment keys: self.metainfos[infohash]['micropayments'] not found "+infohash)
        #    return False
        print("generate payment keys:after arg checks trying to extract "+infohash.encode('hex'))
        #this way, no need to differntiate between multi and single file mode, consumes more mem because of pieces
        #that need to be stored in mem
        metainfo = self.metainfos[infohash]
        print "meta info: "+str(type(metainfo)) 
        print "meta info name: "+ str(metainfo.name)
        hashes = metainfo.hashes
        
        
        piece_count = len( self.metainfos[infohash].hashes)
        print "piece count %d" % piece_count
        payment_keys = []
        for key_num in range(0,piece_count):
             #TODO create real random keys, easy counter  is for debuging
             #TODO move keys maybe to file, because of memory consumption
             #TODO make keygenartion asyncronous task and retrieve from a sort of buffer
             payment_keys.append( "%020d" % key_num)
        print "hex peer id is %s" % myid.encode('hex')
        if infohash not in self.micropaid_downloads:
            self.micropaid_downloads[infohash]= {}
        self.micropaid_downloads[infohash][myid]=payment_keys
        return payment_keys
    
    def get_payment_key_hash_list(self, infohash, myid):
        key_list = self.micropaid_downloads[infohash][myid]
        key_hash_list = [sha(key).hexdigest() for key in key_list ]
        concat_key_hashes = "".join(key_hash_list)
        return concat_key_hashes
    
    """checks the signature of the query string """
    
    def check_signature_of_query(self,sig,query,cert_peer):
             if cert_peer == None:
                 print "no peer certficate"
                 return False
             pubkey_peer = cert_peer.publicKey
             sig_param_idx = query.index("&sig")
             query_without_sig = query[:sig_param_idx]
             print "query wihout sig: %s" % query_without_sig
             #TODO create pk_tools instance
             sig_ok = self.pk_tools.check_sha_signature_tls(pubkey_peer,sig,query_without_sig)
             print "after checking sig result %d" % sig_ok
             return sig_ok
             
    def update_peer_certificates(self,old_peer_certificates,path):
        file_list = os.listdir(path)
        cert_dict = {}
        print "in update peer certificates"
        for file in file_list:
            if file[-4:] == ".pem": 
                print "pem file: %s" % file
                s = open(path+"/"+file).read()
                cert =  self.pk_tools.parse_certificate_string(s)
                cn = self.pk_tools.get_common_name_from_cert(cert)
                print "storing cert for cn= %s" % cn
                cert_dict[cn]= cert
        return cert_dict
         

def track(args):
    assert type(args) == list and \
           len([x for x in args if type(x)==str])==len(args)

    config = {}
    defaults = get_defaults('bittorrent-tracker')   # hard-coded defaults.
    try:
        config, files = parse_configuration_and_args(defaults,
           'bittorrent-tracker', args, 0, 0 )
    except ValueError, e:
        print _("error: ") + str_exc(e)
        print _("run with -? for parameter explanations")
        return
    except BTFailure, e:
        print _("error: ") + str_exc(e)
        print _("run with -? for parameter explanations")
        return

    if config['dfile']=="":
        config['dfile'] = decode_from_filesystem(
            os.path.join(platform.get_temp_dir(), efs2(u"dfile") +
            str(os.getpid())))

    config = Preferences().initWithDict(config)
    ef = lambda e: errorfunc(logging.WARNING, e)
    platform.write_pid_file(config['pid'], ef)

    t = None
    try:
        r = RawServer(config)
        t = Tracker(config, r)
        try:
            #DEBUG
            print "track: create_serversocket, port=", config['port']
            #END
            s = r.create_serversocket(config['port'], config['bind'])
            handler = HTTPHandler(t.get, config['min_time_between_log_flushes'])
            r.start_listening(s, handler)
        except socket.error, e:
            print ("Unable to open port %d.  Use a different port?" %
                   config['port'])
            return

        r.listen_forever()
    finally:
        if t: t.save_dfile()
        print _("# Shutting down: ") + isotime()


def size_format(s):
    return str(Size(s))

def errorfunc( level, text ):
    print "%s: %s" % (logging.getLevelName(level), text)


     
    
