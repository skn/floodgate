# The contents of this file are subject to the BitTorrent Open Source License
# Version 1.1 (the License).  You may not copy or use this file, in either
# source code or executable form, except in compliance with the License.  You
# may obtain a copy of the License at http://www.bittorrent.com/license/.
#
# Software distributed under the License is distributed on an AS IS basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied.  See the License
# for the specific language governing rights and limitations under the
# License.

# Written by Bram Cohen, Greg Hazel, and David Harrison

if __name__ == "__main__":
    # for unit-testing.
    import sys
    sys.path.append("..")

import sys
from BitTorrent.CurrentRateMeasure import Measure
import BitTorrent.Connector
from BTL.hash import sha
import struct
from struct import pack,unpack
import logging
elogger = logging.getLogger("ez")
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
ch.setFormatter(formatter)
elogger.addHandler(ch)
elog = elogger.debug
log = elogger.debug

# Maximum number of outstanding requests from a peer
MAX_REQUESTS = 256
MAX_REWARD_RETRIES = 1000000000
MAX_UNREWARDED_UPLOADS = 1
P_KEY_LENGTH = 20

def _compute_allowed_fast_list(infohash, ip, num_fast, num_pieces):
    
    # if ipv4 then  (for now assume IPv4)
    iplist = [int(x) for x in ip.split(".")]

    # classful heuristic.
    iplist = [chr(iplist[0]),chr(iplist[1]),chr(iplist[2]),chr(0)]
    h = "".join(iplist)
    h = "".join([h,infohash])
    fastlist = []
    assert num_pieces < 2**32
    if num_pieces <= num_fast:
        return range(num_pieces) # <---- this would be bizarre
    while True:
        h = sha(h).digest() # rehash hash to generate new random string.
        for i in xrange(5):
            j = i*4
            #y = [ord(x) for x in h[j:j+4]]
            #z = (y[0] << 24) + (y[1]<<16) + (y[2]<<8) + y[3]
            z = struct.unpack("!L", h[j:j+4])[0]
            index = int(z % num_pieces)
            if index not in fastlist:
                fastlist.append(index)
                if len(fastlist) >= num_fast:
                    return fastlist

class Upload(object):
    """Upload over a single connection."""
    
    def __init__(self, multidownload, connector, ratelimiter, choker, storage, 
                 max_chunk_length, max_rate_period, num_fast, infohash):
        assert isinstance(connector, BitTorrent.Connector.Connector)
        self.multidownload = multidownload
        self.connector = connector
        self.ratelimiter = ratelimiter
        self.infohash = infohash 
        self.choker = choker
        self.num_fast = num_fast
        self.storage = storage
        self.max_chunk_length = max_chunk_length
        self.choked = True
        self.unchoke_time = None
        self.interested = False
        self.had_length_error = False
        self.had_max_requests_error = False
        self.buffer = []    # contains piece data about to be sent.
        self.measure = Measure(max_rate_period)
        connector.add_sent_listener(self.measure.update_rate) 
        self.allowed_fast_pieces = []
        if connector.uses_fast_extension:
            if storage.get_amount_left() == 0:
                connector.send_have_all()
            elif storage.do_I_have_anything():
                connector.send_bitfield(storage.get_have_list())
            else:
                connector.send_have_none()
            self._send_allowed_fast_list()
        elif storage.do_I_have_anything():
            connector.send_bitfield(storage.get_have_list())
        self.unchecked_key_rewards ={} #hash of peerId of pieces(idx,offset,len) with keys als values
        self.blocked_piece_requests = []
        self.uploaded_piece_status ={}  #(idx,offset,lenght) : ("done"|"waiting"| "failed", retries)
        self.own_certificate_is_sent_to_peer = False #whether we have sent our certficate to the other side already  
        
        self.elogger = logging.getLogger("ez")
        print "elogger",self.elogger
        ch = logging.StreamHandler(sys.stdout)
        ch.setLevel(logging.DEBUG)
        formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        ch.setFormatter(formatter)
        elogger.addHandler(ch)


    def _send_allowed_fast_list(self):
        """Computes and sends the 'allowed fast' set.  """
        self.allowed_fast_pieces = _compute_allowed_fast_list(
                        self.infohash,
                        self.connector.ip, self.num_fast,
                        self.storage.get_num_pieces())

        for index in self.allowed_fast_pieces:
            self.connector.send_allowed_fast(index)

    def _compute_allowed_fast_list(self,infohash,ip, num_fast, num_pieces):
        
        # if ipv4 then  (for now assume IPv4)
        iplist = [int(x) for x in ip.split(".")]

        # classful heuristic.
        if iplist[0] | 0x7F==0xFF or iplist[0] & 0xC0==0x80: # class A or B
            iplist = [chr(iplist[0]),chr(iplist[1]),chr(0),chr(0)]
        else:
            iplist = [chr(iplist[0]),chr(iplist[1]),chr(iplist[2]),chr(0)]
        h = "".join(iplist)
        h = "".join([h,infohash])
        fastlist = []
        assert num_pieces < 2**32
        if num_pieces <= num_fast:
            return range(num_pieces) # <---- this would be bizarre
        while True:
            h = sha(h).digest() # rehash hash to generate new random string.
            #log("infohash=%s" % h.encode('hex'))
            for i in xrange(5):
                j = i*4
                y = [ord(x) for x in h[j:j+4]]
                z = (y[0] << 24) + (y[1]<<16) + (y[2]<<8) + y[3]
                index = int(z % num_pieces)
                #log("z=%s=%d, index=%d" % ( hex(z), z, index ))
                if index not in fastlist:
                    fastlist.append(index)
                    if len(fastlist) >= num_fast:
                        return fastlist

    def got_not_interested(self):
        if self.interested:
            self.interested = False
            self.choker.not_interested(self.connector)

    def got_interested(self):
        if not self.interested:
            self.interested = True
            self.choker.interested(self.connector)

    def get_upload_chunk(self, index, begin, length):
        df = self.storage.read(index, begin, length)
        df.addCallback(lambda piece: (index, begin, piece))
        df.addErrback(self._failed_get_upload_chunk)
        return df

    def _failed_get_upload_chunk(self, f):
        self.elogger.warn("get_upload_chunk failed", exc_info=f.exc_info())
        self.connector.close()
        return f

    def got_mp_request(self,index, begin, length,der_cert,sig):
        self.elogger.warn("LOG 4P\n LOG 4P\n LOG4P\n")
        self.elogger.warn("got bad request invalid cert i=%d o=%d l=%d" % (index,begin,length))
        peer_cert = self.connector.download.got_cert(der_cert)
        if not peer_cert:
            self.elogger.warn("got bad request invalid cert i=%d o=%d l=%d " % (index,begin,length))
            return
        msg_to_sign = pack("!iii",index,begin,length)
        msg_ok = self.multidownload.pk_tools.check_signature_tls(peer_cert.publicKey,sig,msg_to_sign)
        if msg_ok:
            self.got_request(index, begin, length)
        else:
            self.elogger.warn("got bad request i=%d o=%d l=%d " % (index,begin,length))
    
    def got_request(self, index, begin, length):
        if not self.interested:
            self.connector.protocol_violation("request when not interested")
            self.connector.close()
            return
        if length > self.max_chunk_length:
            if not self.had_length_error:
                m = ("request length %r exceeds max %r" %
                     (length, self.max_chunk_length))
                self.connector.protocol_violation(m)
                self.had_length_error = True
            #self.connector.close()
            # we could still download...
            if self.connector.uses_fast_extension:
                self.connector.send_reject_request(index, begin, length)
            return
        if len(self.buffer) > MAX_REQUESTS:
            if not self.had_max_requests_error:
                m = ("max request limit %d" % MAX_REQUESTS)
                self.connector.protocol_violation(m)
                self.had_max_requests_error = True
            if self.connector.uses_fast_extension:
                self.connector.send_reject_request(index, begin, length)
            return
        #EZ if micropyaments, check outstanding upload rewards en send reminders
        if self.multidownload.micropayments:
            self.elogger.warn( "mircopayment true in upload")
            if self.connector.id in self.multidownload.waiting_for_reward \
               and len(self.multidownload.waiting_for_reward[self.connector.id]) > 0:
                print("waiting for reward true in upload, so returning after sending requests")
                #if len(self.multidownload.waiting_for_reward[self.connector.id]) > MAX_UNREWARDED_UPLOADS:
                print("adding request to blocked_piece_requests")
                waiting_for_piece_rewards = self.multidownload.waiting_for_reward[self.connector.id]
                self.blocked_piece_requests.append((index, begin, length))
                    #ez: iterate to send all responses 
                for (index,begin,length) in  waiting_for_piece_rewards:
                    print( "upload: sending key request to downloader for piece %d" % index)
                    self.send_key_reward_response(index,begin,length,False)
                return
        
        if index in self.allowed_fast_pieces or not self.connector.choke_sent:
            df = self.get_upload_chunk(index, begin, length)
            df.addCallback(self._got_piece)
            df.addErrback(self.multidownload.errorfunc)
        elif self.connector.uses_fast_extension:
            self.connector.send_reject_request(index, begin, length)
        
        
    def _got_piece(self, piece_info):
        index, begin, piece = piece_info
        if self.connector.closed:
            return
        if self.choked:
            if not self.connector.uses_fast_extension:
                return
            if index not in self.allowed_fast_pieces:
                self.connector.send_reject_request(index, begin, len(piece))
                return
        if self.multidownload.micropayments:
           if self.connector.id not in self.multidownload.waiting_for_reward:
               self.multidownload.waiting_for_reward[self.connector.id] =[]
           self.multidownload.waiting_for_reward[self.connector.id].append((index,begin,len(piece)))
           if not self.own_certificate_is_sent_to_peer:
               der_cert = self.multidownload.certificate.bytes.tostring()
               self.own_certificate_is_sent_to_peer = True
               self.connector.download.own_certificate_is_sent_to_peer = True
           else:
               der_cert = "" #leave out the certfificate because other side alread has it
           self.elogger.warn("length of der cert = %d" % len(der_cert))
           #todo do this before instead of realtime
           piece_sig = self.multidownload.pk_tools.get_sha_signature_tls(self.multidownload.private_key,piece)
           self.elogger.warn("index= %d, begin=%d, len(piece)=%d,len(piece_sig)%d lendercert = %d" %(index, begin, len(piece),len(piece_sig),len(der_cert) ))
           self.buffer.append(((index, begin, len(piece),len(piece_sig),len(der_cert)), piece,piece_sig,der_cert))
        else:
            self.buffer.append(((index, begin, len(piece)), piece))
        
        if self.connector.next_upload is None and \
               self.connector.connection.is_flushed():
            self.ratelimiter.queue(self.connector)
        
        
            
    def got_cancel_mp(self,index, begin, length):
        self.elogger.warn("got mp cancel")
        req = (index, begin, length)
        for entry in enumerate(self.buffer):
            pos, ((p_index, p_begin, p_length,length_sig,length_cert), p,p_sig,p_cert) = entry
            buffer_req = (p_index, p_begin, p_length)
            if  buffer_req == req:
                del self.buffer[pos]
                if self.connector.uses_fast_extension:
                    self.connector.send_reject_request(*req)
                break
            
    
    def got_cancel(self, index, begin, length):
        if self.multidownload.micropayments:
            self.got_cancel_mp(index, begin, length)
            return
        log("got non mp cancel")    
        req = (index, begin, length)
        for pos, (r, p) in enumerate(self.buffer):
            if r == req:
                del self.buffer[pos]
                if self.connector.uses_fast_extension:
                    self.connector.send_reject_request(*req)
                break

    def choke(self):
        if not self.choked:
            self.choked = True
            self.connector.send_choke()

    def sent_choke_mp(self):
        assert self.choked
        if self.connector.uses_fast_extension:
            b2 = []
            for r in self.buffer:
                ((index, begin, length,length_sig,length_cert), p,p_sig,p_cert) = r
                if index not in self.allowed_fast_pieces:
                    self.connector.send_reject_request(index, begin, length)
                else:
                    b2.append(r)
            self.buffer = b2
        else:
            del self.buffer[:]
    
    
    
    def sent_choke(self):
        assert self.choked
        if self.multidownload.micropayments:
            self.sent_choke_mp()
            return
        if self.connector.uses_fast_extension:
            b2 = []
            for r in self.buffer:
                ((index,begin,length),piecedata) = r
                if index not in self.allowed_fast_pieces:
                    self.connector.send_reject_request(index, begin, length)
                else:
                    b2.append(r)
            self.buffer = b2
        else:
            del self.buffer[:]

    def unchoke(self, time):
        if self.choked:
            self.choked = False
            self.unchoke_time = time
            self.connector.send_unchoke()

    def has_queries(self):
        return len(self.buffer) > 0

    def get_rate(self):
        return self.measure.get_rate()
    
    
    #EZ
    def send_key_reward_response(self,index,begin,length,good):
        """
         Send a response to the keyreward received to indicate if it could be validated.
         Validation of the key reward is checking if the sha1 hash of the reward is the
         same as the hashed reward received from the tracker.
         
         @param index: index of the piece (piece number), 
           a piece is a block of which the has is in the meta file
         @param begin: offset of the subpiece is the piece,
           this is currently always zero, this enables to account a single piece
           hashcheck failing to single peer. 
         @param length: length of the piece 
         @return: nothing 
        """
        self.connector.send_key_reward_response(index,begin,length,good)
        
    def got_key_reward(self,index, begin, length,key):
        """
         Process a received key reward. Compares hash of keyreward with received
         hash from tracker. If hash from tracker not present, a tracker request is made to retrieve it.
         If the key is OK any pending requests that were blocked
         are now unblocked.
         A key reward reponse is send. 
         
         @param index: index of the piece (piece number), 
           a piece is a block of which the has is in the meta file
         @param begin: offset of the subpiece is the piece,
           this is currently always zero, this enables to account a single piece
           hashcheck failing to single peer. 
         @param length: length of the piece 
         @return: nothing 
        """
        
        log("in got key reward for piece %d %d %d and key [%s] len key=%d" % (index, begin, length,key.encode('hex'),len(key)))
        
        if len(key) < 127 :
            log( "received empty/too small key  got_key_reward indicating bad payment key")
            proceed = self.update_upload_key_status(index,begin,length,False)
            if not proceed:
                log( "too many retries.. in upload (update key status)")
                return
            self.got_request(index, begin, length)
            return
        
        if (not self.connector.id in self.multidownload.payment_key_hash_cache.keys()) or\
         self.multidownload.payment_key_hash_cache[self.connector.id] == {}:
            self.elogger.warn( "downlaod. got_key_reward no key_cache, so retrieve first")
            if self.connector.id not in  self.multidownload.payment_key_hash_cache.keys():
                self.elogger.warn( "dl: initializing payment_key_hash_cache to {}")
                self.multidownload.payment_key_hash_cache[self.connector.id] = {}
            self.elogger.warn( "calling rerequester.get_key_hash_list_for_peer()")
            self.multidownload.rerequester.get_key_hash_list_for_peer(self.connector.id,self.got_key_hash_list)
            if self.connector.id not in self.unchecked_key_rewards:
                self.elogger.warn( "initializing unchecked key rewards")
                self.unchecked_key_rewards[self.connector.id] = {}
            self.unchecked_key_rewards[self.connector.id][(index, begin, length)] = key
            self.elogger.warn( "added key to unchecked rewarsd")
            return
        
        self.elogger.warn("cached keys of peer already available")
        self.elogger.warn( "encrypted key reward hex: %s" % key.encode('hex'))
        key = self.multidownload.pk_tools.decrypt_piece_tls(self.multidownload.private_key,key)
        self.elogger.warn("decrypted key reward: "+key)
        key_cache = self.multidownload.payment_key_hash_cache[self.connector.id] 
        self.elogger.warn( "comparing recvd %s, to stored %s" % (key_cache[(index, begin, length)],sha(key).hexdigest()))
        result = (key_cache[(index, begin, length)] == sha(key).hexdigest())
        print( "result is %d" % result)
        self.send_key_reward_response(index,begin,length,result)
        print( "after send key reward response")
        if result:
            print( "key matches stored key")
            if self.connector.id in self.multidownload.waiting_for_reward:
                print( "waiting for reward true in upload")
                self.elogger.warn( "waiting for reward true in upload")
                waiting_for_piece_rewards = self.multidownload.waiting_for_reward[self.connector.id]
                #ez: iterate to send all responses 
                if (index,begin,length) in  waiting_for_piece_rewards:
                    self.elogger.warn("removing from waiting for keys: %d" % index)
                    waiting_for_piece_rewards.remove((index,begin,length))
                    if self.blocked_piece_requests:
                        (bidx,bbegin,blen) = self.blocked_piece_requests.pop()
                        print( "sending blocked request to got_request: %d %d %d" % (bidx,bbegin,blen))
                        self.got_request(bidx,bbegin,blen)
                else:
                    self.elogger.warn( "received key but wasnt waiting for it (error in code)")
            self.elogger.warn( "not waiting for reward from this peer")   
        else:
            self.elogger.warn( "recieved bad key")
            
    
    def update_upload_key_status(self, index,offset,length,success):
          """
          Change status of reward that has been sent.
          Status contains textual status and retries
          Textual status can be waiting | done | failed
          waiting: still waiting for key reward response
          done: key reward response received
          failed: too many retries
          
          @param index: piecenumber that the key reward was for
          @param offset: offset in piece of the subpiece that the key reward was for (always 0)
          @param length: length of piece that the keyreward was for
          
          @return boolean that signifies if any further attempt to send the reward must be done.
          """
          
          if (self, index,offset) not in self.uploaded_piece_status:
              self.uploaded_piece_status[(self, index,offset)] = ("waiting",0)
          (status, retries) = self.uploaded_piece_status[(self, index,offset)]
          if success == True:
              status = "done"
          else:
              if status == "failed":
                  return False
              retries +=1
              if(retries > MAX_REWARD_RETRIES):
                  status = "failed"
              else:
                  status = "waiting"
          self.uploaded_piece_status[(self, index,offset)] = (status,retries)
          return retries < MAX_REWARD_RETRIES
          
    
            
    def got_key_hash_list(self, peerid, keyhashliststring):
        """
         Callback function called from the Rerequester when a keyhashlist is 
         received from the tracker
         The received string is put in a dictionary with a piece identifier
         (piecenr,offset,len) as dictonarykeyword and the keyhash as value.
         
         The keyhashlist is a list of hashed payment keys, that is used to check
         the validity of received payment keys.
         
         @param peerid: The peerid of the peer the keyhashlist is for
         @param keyhashliststring: A string of concatenated hex encoded keyhashes.
        """
        
        keyhashliststring = self.multidownload.pk_tools.decrypt_piece_tls(self.multidownload.private_key, keyhashliststring.decode('hex'))
        
        self.elogger.warn( "setting hashes of keys")
        piece_length = self.storage.piece_size
        key_length = P_KEY_LENGTH*2
        keylist_length = len(keyhashliststring)
        keyhashlist = {}
        for idx in range(0,keylist_length/key_length): 
            start = idx * key_length
            if idx == self.storage.numpieces -1:
                piece_length = self.storage.lastlen
                self.elogger.warn( "setting last key length to %d" % key_length)
            keyhashlist[(idx,0,piece_length)]=keyhashliststring[start:(start+key_length)]  
            print "set keyhashnumber %d to %s" % (idx,keyhashliststring[start:(start+key_length)])     

        self.multidownload.payment_key_hash_cache[self.connector.id] = keyhashlist
        #todo move to multidownload
        self.elogger.warn("validating unchecked rewards")
        for (index,offset,length) in self.unchecked_key_rewards[peerid].keys():
            key_to_check = self.unchecked_key_rewards[peerid][(index,offset,length)]
            self.got_key_reward(index,offset,length,key_to_check)
            self.unchecked_key_rewards[peerid].pop((index,offset,length))
             

if __name__ == "__main__":
    # unit tests for allowed fast set generation.
    n_tests = n_tests_passed = 0
    infohash = "".join( ['\xaa']*20 )  # 20 byte string containing all 0xaa.
    ip = "80.4.4.200"
    expected_list = [1059,431,808,1217,287,376,1188]

    n_tests += 1
    fast_list =_compute_allowed_fast_list(
                        infohash, ip, num_fast = 7, num_pieces = 1313 )
    if expected_list != fast_list:
        print ( "FAIL!! expected list = %s, but got %s" %
            (str(expected_list), str(fast_list)) )
    else:
        n_tests_passed += 1

    n_tests += 1
    expected_list.extend( [353,508] )
    fast_list =_compute_allowed_fast_list(
                        infohash, ip, num_fast = 9, num_pieces = 1313 )
    if expected_list != fast_list:
        print ("FAIL!! expected list = %s, but got %s" %
            (str(expected_list), str(fast_list)))
    else:
        n_tests_passed += 1

    if n_tests == n_tests_passed:
        print "Success. Passed all %d unit tests." % n_tests
    else:
        print "Passed only %d out of %d unit tests." % (n_tests_passed,n_tests)



    
