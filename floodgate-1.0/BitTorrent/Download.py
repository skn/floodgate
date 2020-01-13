# The contents of this file are subject to the BitTorrent Open Source License
# Version 1.1 (the License).  You may not copy or use this file, in either
# source code or executable form, except in compliance with the License.  You
# may obtain a copy of the License at http://www.bittorrent.com/license/.
#
# Software distributed under the License is distributed on an AS IS basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied.  See the License
# for the specific language governing rights and limitations under the
# License.

# Written by Bram Cohen, Uoti Urpala, David Harrison, and Greg Hazel

import random
import logging
import struct
from struct import pack, unpack

from BTL.obsoletepythonsupport import *
from BTL.platform import bttime
from BitTorrent.CurrentRateMeasure import Measure
from BTL.bitfield import Bitfield


logger = logging.getLogger("BitTorrent.Download")
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
ch.setFormatter(formatter)
logger.addHandler(ch)
log = logger.info
MAX_REWARD_RETRIES = 10000

class BadDataGuard(object):

    def __init__(self, download):
        self.download = download
        self.ip = download.connector.ip
        self.multidownload = download.multidownload
        self.stats = self.multidownload.perip[self.ip]
        self.lastindex = None

    def bad(self, index, bump = False):
        if self.multidownload.micropayments:
            if (multidownload.storage.numpieces-1) == index:
                    length = multidownload.storage.lastlen;
            else:
                    length = multidownload.storage.piece_size; 
            self.download.send_key_reward(index,0,length,good=False)
        self.stats.bad.setdefault(index, 0)
        self.stats.bad[index] += 1
        if self.ip not in self.multidownload.bad_peers:
            self.multidownload.bad_peers[self.ip] = (False, self.stats)
        if self.download is not None:
            self.multidownload.kick(self.download)
            self.download = None
        elif (len(self.stats.bad) > 1 and self.stats.numconnections == 1 and
              self.stats.lastdownload is not None):
            # kick new connection from same IP if previous one sent bad data,
            # mainly to give the algorithm time to find other bad pieces
            # in case the peer is sending a lot of bad data
            self.multidownload.kick(self.stats.lastdownload)
        if len(self.stats.bad) >= 3 and len(self.stats.bad) > \
           self.stats.numgood // 30:
            self.multidownload.ban(self.ip)
        elif bump:
            self.multidownload.active_requests_remove(index)
            self.multidownload.picker.bump(index)

    def good(self, index):
        # lastindex is a hack to only increase numgood for by one for each good
        # piece, however many chunks came from the connection(s) from this IP
        if index != self.lastindex:
            self.stats.numgood += 1
            self.lastindex = index
        if self.multidownload.micropayments:
            if (self.multidownload.storage.numpieces-1) == index:
                    length = self.multidownload.storage.lastlen
            else:
                    length = self.multidownload.storage.piece_size
            print("download. dataguard. good piece %d" % index)
            if(self.download): 
                #piece gets checked later than it is received, so it's possible
                #that the uploader has already left the swarm
                self.download.send_key_reward(index,0,length,good=True)

class Download(object):
    """Implements BitTorrent protocol semantics for downloading over a single
       connection.  See Upload for the protocol semantics in the upload
       direction.  See Connector for the protocol syntax implementation."""
       

    def __init__(self, multidownload, connector):
        self.multidownload = multidownload
        self.connector = connector
        self.choked = True
        self.interested = False
        self.prefer_full = False
        self.active_requests = set()
        self.expecting_reject = set()
        self.intro_size = self.multidownload.chunksize * 4 # just a guess
        self.measure = Measure(multidownload.config['max_rate_period'])
        self.peermeasure = Measure(
            max(multidownload.storage.piece_size / 10000, 20))
        self.have = Bitfield(multidownload.numpieces)
        self.last = 0
        self.example_interest = None
        self.guard = BadDataGuard(self)
        self.suggested_pieces = []
        self.allowed_fast_pieces = []
        self._useful_received_listeners = set()
        self._raw_received_listeners = set()
        
        self.add_useful_received_listener(self.measure.update_rate)
        self.total_bytes = 0
        self.add_useful_received_listener(self.accumulate_total)
        
        self.payment_key_status ={} #hash with retries of sending payment key: key=(idx,offset,len) val ("statustring",retries)
                                    #todo move to multidownload, and later to seperate package
        self.peer_certificate = None
        self.own_certificate_is_sent_to_peer = False
        
    def accumulate_total(self, x):
        self.total_bytes += x        

    def add_useful_received_listener(self, listener):
        # "useful received bytes are used in measuring goodput.
        self._useful_received_listeners.add(listener)

    def remove_useful_received_listener(self, listener):
        self._useful_received_listeners.remove(listener)

    def fire_useful_received_listeners(self, bytes):
        for f in self._useful_received_listeners:
            f(bytes)

    def add_raw_received_listener(self, listener):
        self._raw_received_listeners.add(listener)

    def remove_raw_received_listener(self, listener):
        self._raw_received_listeners.remove(listener)

    def fire_raw_received_listeners(self, bytes):
        for f in self._raw_received_listeners:
            f(bytes)

    def _backlog(self):
        # Dave's suggestion:
        # backlog = 2 + thruput delay product in chunks.
        # Assume one-way download propagation delay is always less than 200ms.
        # backlog = 2 + int(0.2 * self.measure.get_rate() / 
        #                 self.multidownload.chunksize
        # Then eliminate the cap of 50 and the 0.075*backlog. 

        backlog = 2 + int(4 * self.measure.get_rate() /
                          self.multidownload.chunksize)
        if self.total_bytes < self.intro_size:
            # optimistic backlog to get things started
            backlog = max(10, backlog)
        if backlog > 50:
            backlog = max(50, int(.075 * backlog))

        if self.multidownload.rm.endgame:
            # OPTIONAL: zero pipelining during endgame
            #b = 1
            pass

        return backlog

    def disconnected(self):
        self.multidownload.lost_peer(self)
        if self.have.numfalse == 0:
            self.multidownload.lost_have_all()
        else:
            # arg, slow
            count = 0
            target = len(self.have) - self.have.numfalse
            for i in xrange(len(self.have)):
                if count == target:
                    break
                if self.have[i]:
                    self.multidownload.lost_have(i)
                    count += 1
        self._letgo()
        self.guard.download = None
        
    def _letgo(self):
        if not self.active_requests:
            return
        if self.multidownload.rm.endgame:
            self.active_requests.clear()
            return
        lost = []
        for index, begin, length in self.active_requests:
            self.multidownload.rm.request_lost(index, begin, length)
            self.multidownload.active_requests_remove(index)
            if index not in lost:
                lost.append(index)
        self.active_requests.clear()
        ds = [d for d in self.multidownload.downloads if not d.choked]
        random.shuffle(ds)
        for d in ds:
            d._request_more(lost)
        for d in self.multidownload.downloads:
            if d.choked and not d.interested:
                for l in lost:
                    if d._want(l):
                        d.interested = True
                        d.connector.send_interested()
                        break
        
    def got_choke(self):
        if not self.choked:
            self.choked = True
            if not self.connector.uses_fast_extension:
                self._letgo()
        
    def got_unchoke(self):
        if self.choked:
            self.choked = False
            if self.interested:
                self._request_more()

    
    
    def got_cert(self, cert):
        """
         checks certificate and stores it into an object from which 
         the public public key can be read
         
         @param cert: a DER encoded X509 certificate string 
         @return: the certificate object or None in case of an invalid certificate         
        """
        if self.peer_certificate and not cert:
            return self.peer_certificate
       
        print "before parsing der certficate in got_cert length= %d" % len(cert)
        peer_certificate = self.multidownload.pk_tools.parseDERCert_tls(cert)
        print "after parsing cert = %s" % str(peer_certificate)
        if peer_certificate == self.peer_certificate and self.peer_certificate is not None : #maybe also check if not none
            print "peer certificate already present so skipping check lencer = %d == len self.cert %d" % (len(peer_certificate),len(self.peer_certificate))
            return peer_certificate
        else:
           cert_ok = self.multidownload.pk_tools.validate_in_mem_certificate(peer_certificate) 
           if cert_ok:
               print "peer certificate validated"
               self.peer_certificate = peer_certificate
               return peer_certificate
           else:
               print "peer certificate NOT OK!!!"
               return None
           
    def got_mp_piece(self, index, begin, piece, sig):
        """
         check if the certificate and the signature of the received piece message are OK
         if they are OK process piece with got_piece, otherwise send a empty keyreward message
         
         @param index: index of the piece (piece number), 
           a piece is a block of which the has is in the meta file
         @param begin: offset of the subpiece is the piece,
           this is currently always zero, this enables to account a single piece
           hashcheck failing to single peer. 
         @param piece: The piece itself 
         @param sig: the signature of the piece , created by encrypting a zero padded
          sha-1 hash.
         @return: nothing 
        """
        
        if self.peer_certificate and self.peer_certificate.publicKey:
                    
            sig_ok = self.multidownload.pk_tools.check_sha_signature_tls(self.peer_certificate.publicKey,sig,piece)
            print "after checking signature sig_OK is %d" % sig_ok
            if sig_ok:
                print "signature ok in got_mp_piece"
                self.got_piece(index,begin,piece)
                return
            else:
                print "signature not OK in got_mp_piece"
        #TODO maybe also increment retries
        else:
            print "no peer certificate or certificate.publickey"
            print "cert= %s\n\n\n publicKey= %s" % (str(self.peer_certificate),str(self.peer_certificate.publicKey))
        self.send_key_reward(index,begin,len(piece),False)
    
    def got_piece(self, index, begin, piece):
        req = (index, begin, len(piece))

        if req not in self.active_requests:
            self.multidownload.discarded_bytes += len(piece)
            if self.connector.uses_fast_extension:
                # getting a piece we sent a cancel for
                # is just like receiving a reject
                self.got_reject_request(*req)
            return

        self.active_requests.remove(req)
        
        # we still give the peer credit in endgame, since we did request
        # the piece (it was in active_requests)
        self.fire_useful_received_listeners(len(piece))

        if self.multidownload.rm.endgame:
            if req not in self.multidownload.all_requests:
                self.multidownload.discarded_bytes += len(piece)
                return

            self.multidownload.all_requests.remove(req)

            for d in self.multidownload.downloads:
                if d.interested:
                    if not d.choked and req in d.active_requests:
                        d.connector.send_cancel(*req)
                        d.active_requests.remove(req)
                        if d.connector.uses_fast_extension:
                            d.expecting_reject.add(req)
                    d.fix_download_endgame()
        else:
            self._request_more()
            
        self.last = bttime()
        df = self.multidownload.storage.write(index, begin, piece, self.guard)
        df.addCallback(self._got_piece, index)
        df.addErrback(self.multidownload.errorfunc)

    def _got_piece(self, hashchecked, index):
        if hashchecked:
            self.multidownload.hashchecked(index)
        
    def _want(self, index):
        return (self.have[index] and 
                self.multidownload.rm.want_requests(index))

    def send_request(self, index, begin, length):
        piece_size = self.multidownload.storage.piece_size
        if begin + length > piece_size:
            raise ValueError("Issuing request that exceeds piece size: "
                             "(%d + %d == %d) > %d" %
                             (begin, length, begin + length, piece_size))
        self.multidownload.active_requests_add(index)
        self.active_requests.add((index, begin, length))
        if self.multidownload.micropayments:
            msg_to_sign = pack("!iii",index,begin,length)
            sig = self.multidownload.pk_tools.get_signature_tls(self.multidownload.private_key, msg_to_sign)
            if self.own_certificate_is_sent_to_peer:
                cert_to_send = ""
            else:
                cert_to_send = self.multidownload.certificate.writeBytes().tostring()
                self.own_certificate_is_sent_to_peer = True
                self.connector.upload.own_certificate_is_sent_to_peer = True
            self.connector.send_mp_request(index, begin, length,sig,cert_to_send)
        else:
            self.connector.send_request(index, begin, length)

    def _request_more(self, indices = []):
        
        if self.choked:
            self._request_when_choked()
            return
        #log( "_request_more.active_requests=%s" % self.active_requests )
        b = self._backlog()
        if len(self.active_requests) >= b:
            return
        if self.multidownload.rm.endgame:
            self.fix_download_endgame()
            return

        self.suggested_pieces = [i for i in self.suggested_pieces 
            if not self.multidownload.storage.do_I_have(i)]
        lost_interests = []
        while len(self.active_requests) < b:
            if not indices:
                interest = self.multidownload.picker.next(self.have,
                                    self.multidownload.rm.active_requests,
                                    self.multidownload.rm.fully_active,
                                    self.suggested_pieces)
            else:
                interest = None
                for i in indices:
                    if self._want(i):
                        interest = i
                        break
            if interest is None:
                break
            if not self.interested:
                self.interested = True
                self.connector.send_interested()
            # an example interest created by from_behind is preferable
            if self.example_interest is None:
                self.example_interest = interest

            # request as many chunks of interesting piece as fit in backlog.
            while len(self.active_requests) < b:
                begin, length = self.multidownload.rm.new_request(interest,
                                                                  self.prefer_full)
                self.send_request(interest, begin, length)

                if not self.multidownload.rm.want_requests(interest):
                    lost_interests.append(interest)
                    break
        if not self.active_requests and self.interested:
            self.interested = False
            self.connector.send_not_interested()
        self._check_lost_interests(lost_interests)
        self.multidownload.check_enter_endgame()

    def _check_lost_interests(self, lost_interests):
        """
           Notify other downloads that these pieces are no longer interesting.

           @param lost_interests: list of pieces that have been fully 
               requested.
        """
        if not lost_interests:
            return
        for d in self.multidownload.downloads:
            if d.active_requests or not d.interested:
                continue
            if (d.example_interest is not None and 
                self.multidownload.rm.want_requests(d.example_interest)):
                continue
            # any() does not exist until python 2.5
            #if not any([d.have[lost] for lost in lost_interests]):
            #    continue
            for lost in lost_interests:
                if d.have[lost]:
                    break
            else:
                continue
            interest = self.multidownload.picker.from_behind(d.have,
                            self.multidownload.rm.fully_active)
            if interest is None:
                d.interested = False
                d.connector.send_not_interested()
            else:
                d.example_interest = interest

    def _request_when_choked(self):
        self.allowed_fast_pieces = [i for i in self.allowed_fast_pieces
            if not self.multidownload.storage.do_I_have(i)]
        if not self.allowed_fast_pieces:
            return
        fast = list(self.allowed_fast_pieces)

        b = self._backlog()
        lost_interests = []
        while len(self.active_requests) < b:

            while fast:
                piece = fast.pop()
                if self._want(piece):
                    break
            else:
                break # no unrequested pieces among allowed fast.

            # request chunks until no more chunks or no more room in backlog.
            while len(self.active_requests) < b:
                begin, length = self.multidownload.rm.new_request(piece,
                                                                  self.prefer_full)
                self.send_request(piece, begin, length)
                if not self.multidownload.rm.want_requests(piece):
                    lost_interests.append(piece)
                    break
        self._check_lost_interests(lost_interests)
        self.multidownload.check_enter_endgame()
                
    def fix_download_endgame(self):
        want = []
        for a in self.multidownload.all_requests:
            if not self.have[a[0]]:
                continue
            if a in self.active_requests:
                continue
            want.append(a)

        if self.interested and not self.active_requests and not want:
            self.interested = False
            self.connector.send_not_interested()
            return
        if not self.interested and want:
            self.interested = True
            self.connector.send_interested()
        if self.choked:
            return
        random.shuffle(want)
        for req in want[:self._backlog() - len(self.active_requests)]:
            self.send_request(*req)
        
    def got_have(self, index):
        if self.have[index]:
            return
        if index == self.multidownload.numpieces-1:
            self.peermeasure.update_rate(self.multidownload.storage.total_length-
              (self.multidownload.numpieces-1)*self.multidownload.storage.piece_size)
        else:
            self.peermeasure.update_rate(self.multidownload.storage.piece_size)
        self.have[index] = True
        self.multidownload.got_have(index)
        if (self.multidownload.storage.get_amount_left() == 0 and
            self.have.numfalse == 0):
            self.connector.close()
            return
        if self.multidownload.rm.endgame:
            self.fix_download_endgame()
        elif self.multidownload.rm.want_requests(index):
            self._request_more([index]) # call _request_more whether choked.
            if self.choked and not self.interested:
                self.interested = True
                self.connector.send_interested()
        
    def got_have_bitfield(self, have):
        if have.numfalse == 0:
            self._got_have_all(have)
            return
        self.have = have
        # arg, slow
        count = 0
        target = len(self.have) - self.have.numfalse
        for i in xrange(len(self.have)):
            if count == target:
                break
            if self.have[i]:
                self.multidownload.got_have(i)
                count += 1
        if self.multidownload.rm.endgame:
            for piece, begin, length in self.multidownload.all_requests:
                if self.have[piece]:
                    self.interested = True
                    self.connector.send_interested()
                    return
        for piece in self.multidownload.rm.iter_want():
            if self.have[piece]:
                self.interested = True
                self.connector.send_interested()
                return

    def _got_have_all(self, have=None):
        if self.multidownload.storage.get_amount_left() == 0:
            self.connector.close()
            return
        if have is None:
            # bleh
            n = self.multidownload.numpieces
            rlen, extra = divmod(n, 8)
            if extra:
                extra = chr((0xFF << (8 - extra)) & 0xFF)
            else:
                extra = ''
            s = (chr(0xFF) * rlen) + extra
            have = Bitfield(n, s)
        self.have = have
        self.multidownload.got_have_all()
        if self.multidownload.rm.endgame:
            for piece, begin, length in self.multidownload.all_requests:
                self.interested = True
                self.connector.send_interested()
                return
        for i in self.multidownload.rm.iter_want():
            self.interested = True
            self.connector.send_interested()
            return
        

    def get_rate(self):
        return self.measure.get_rate()

    def is_snubbed(self):
        return bttime() - self.last > self.multidownload.snub_time

    def got_have_none(self):
        pass  # currently no action is taken when have_none is received.
              # The picker already assumes the local peer has none of the
              # pieces until got_have is called.

    def got_have_all(self):
        assert self.connector.uses_fast_extension
        self._got_have_all()

    def got_suggest_piece(self, piece):
        assert self.connector.uses_fast_extension
        if not self.multidownload.storage.do_I_have(piece): 
          self.suggested_pieces.append(piece)
        self._request_more() # try to request more. Just returns if choked.

    def got_allowed_fast(self,piece):
        """Upon receiving this message, the multidownload knows that it is
           allowed to download the specified piece even when choked."""
        #log( "got_allowed_fast %d" % piece )
        assert self.connector.uses_fast_extension

        if not self.multidownload.storage.do_I_have(piece): 
            if piece not in self.allowed_fast_pieces:
                self.allowed_fast_pieces.append(piece)
                random.shuffle(self.allowed_fast_pieces)  # O(n) but n is small.
        self._request_more()  # will try to request.  Handles cases like
                              # whether neighbor has "allowed fast" piece.

    def got_reject_request(self, piece, begin, length):
        assert self.connector.uses_fast_extension
        req = (piece, begin, length) 

        if req not in self.expecting_reject:
            if req not in self.active_requests:
                self.connector.protocol_violation("Reject received for "
                                                  "piece not pending")
                self.connector.close()
                return
            self.active_requests.remove(req)
        else:
            self.expecting_reject.remove(req)

        if self.multidownload.rm.endgame:
            return

        self.multidownload.rm.request_lost(*req)
        if not self.choked:
            self._request_more()
        ds = [d for d in self.multidownload.downloads if not d.choked]
        random.shuffle(ds)
        for d in ds:
            d._request_more([piece])
            
        for d in self.multidownload.downloads:
            if d.choked and not d.interested:
                if d._want(piece):
                    d.interested = True
                    d.connector.send_interested()
                    break


    def got_key_reward_response(self,index, begin, length, result):
        """
         Process a payment key response message. If the response indicates succesful
         reception of the key update status to "done". If the response  indicates
         failure (invalid key or no key recvd) resend key.
         
         The keyreward message is also sent as a reply to a piece request if the 
         downloader has too many outstanding unpaid pieces.
         
         @param index: index of the piece (piece number) the reward is for. 
           A piece is a block of which the has is in the meta file.
         @param begin: offset of the subpiece is the piece the reward is for.
           This is currently always zero, it enables to account a single piece
           hashcheck failing to single peer. 
         @param length: The length of the piece the reward is for. 
         @param result: boolean indicating if the uploader validated the sent key
         @return: nothing 
        """
  
        print("received reward for piece %d %d %d" % (index,begin,length))
        if not (index,begin,length) in self.payment_key_status:
            print("received reward for unsent piece %d %d %d" % (index,begin,length))
            return
        
        (status,retries,old_good) = self.payment_key_status[(index,begin,length)]  
        if status == "done":
            print "received key reward response for already done piece"
            #we already received this one
            return
        elif status == None:
            #something weird happened, received unwanted key
            print("received unwanted key_reward resonse idx=%06d begin=%06d len=%06d key=%s" % (index,begin,len))
            return  
        elif status == "waiting":
            (old_status,old_retries, good) = self.payment_key_status[(index,begin,length)]
            if result != 0:
                #success
               print "received positive key reward response for %d %d %d" % (index,begin,length)
               self.payment_key_status[(index,begin,length)] = ("done",retries, good)
            #elif retries > MAX_REWARD_RETRIES:
                #permanent failure
            #            log("failure, too many retries")
            ##            self.payment_key_status[ (index,begin,length)] = ("failed",retries,good)
            #            self.multidownload.ban(self.ip)
            #            return
            else:
                #temporary failure
                #TODO add check for validity of response
                self.send_key_reward(index,begin,length,good)
                retries+=1
                self.payment_key_status[ (index,begin,length)] = ("waiting",retries,good)
        else:
                print("bad status for key_reward resonse idx=%06d begin=%06d len=%06d key=%s" % (index,begin,len))
                
                
    def send_key_reward(self,index,begin,length,good):
        """
        Send a key reward message. The message may or may not contain the keyreward.
        If the message is send as response to corrupt piece, no keyreward is included.
         
         @param index: index of the piece (piece number) the reward is for. 
           A piece is a block of which the has is in the meta file.
         @param begin: offset of the subpiece is the piece the reward is for.
           This is currently always zero, it enables to account a single piece
           hashcheck failing to single peer. 
         @param length: The length of the piece the reward is for. 
         @param good: boolean indicating if the key reward has to be included.
         @return: nothing 
        """
        print "sending key reward for piece  %d %d %d result= %d" % (index,begin,length,good)
        if  (index,begin,length) not in self.payment_key_status:
            print "first time send reward for piece  %d %d %d result= %d" % (index,begin,length,good)
            self.payment_key_status[ (index,begin,length)] = ("waiting", 0,good)
        (status,retries,good) = self.payment_key_status[ (index,begin,length)]  
        if status == "done":
            print "received double key reward response %d %d %d" %  (index,begin,length)
            #we already received the reward for this one
            return
        if good and (index,begin,length) in self.multidownload.key_rewards: #only send a reward if we already received the keylist from tracker.
            print("sending key reward ")
            key = self.multidownload.key_rewards[(index,begin,length)]
            print "encrypting key:"+key
            key = self.multidownload.pk_tools.encrypt_piece_tls(self.peer_certificate.publicKey, key)
            
                
            print "encrypted key hex %s" % key.encode('hex')  
        else:
            key = "";
            print "sending empty reward"
        self.connector.send_key_reward(index, begin, length,key)
