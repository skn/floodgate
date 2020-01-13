import commands
import re
import os
import stat
from tlslite.api import *
import tlslite
import array
from M2Crypto import SMIME, X509,BIO, m2
import M2Crypto
import sha as shalib
import random
import base64

class PKTools(object):

    """
    create pk tools object
    
    @param ca_path:  The path where a pem file or multiple pem files can be found that are trusted
                    If ca_path is a directory, all pem files in the directory will be concatenated
    @param temp_path: The path where incoming certficates are stored
    """
    def __init__(self, ca_path, temp_path = ""):
        if stat.S_ISDIR(os.stat(ca_path).st_mode):
            outfile = open(temp_path+"/trustedRpBtCerts.pem",'w')
            file_list = os.listdir(ca_path)
            for file_name in file_list:
                if (file_name[-4:] == ".pem"):
                    file=open(path+"/"+file_name,'r')
                    data=file.read()
                    file.close()
                    outfile.write(data)
                outfile.flush()
                outfile.close()       
            self.ca_path = temp_path+"/trustedRpBtCerts.pem"
        else:
            self.ca_path = ca_path
        self.temp_path = temp_path
    
    def parse_certificate_string(self,cert_string):
        return tlslite.X509.X509().parse(cert_string)
    

            
    """get common name of subject from certficate
       @param certficate: certficate to get common name from
    """
    def get_common_name_from_cert(self, certificate):
        cert_bytes_array = certificate.writeBytes()
        cert_bytes = cert_bytes_array.tostring()
        pem_cert = self.der_2_pem_cert(cert_bytes)
        
        if M2Crypto.version >= "0.16":
            m2_cert_obj = M2Crypto.X509.load_cert_string(pem_cert)
            
            
        else:
            temp_file_name = self.temp_path+"/temppeercert_%d" % random.randint(0,100000)
            temp_file = open(temp_file_name,"w")
            temp_file.write(pem_cert)
            temp_file.flush()
            temp_file.close()
            #print("wrote pem cert: \n" + pem_cert+"\n to file:\n"+temp_file_name)
            m2_cert_obj = M2Crypto.X509.load_cert(temp_file_name)
            
            
        #print("extracting subj"+m2_cert_obj)
        subject_obj = m2_cert_obj.get_subject()
        #print("extracting subj string from "+subject_obj)
        subject_string = subject_obj.as_text()
        #print("subject string =" +subject_string)
        subject_list = subject_string.split(", ")
        subject_list_no_space = [e.strip() for e in subject_list]
        print subject_list_no_space 
        for d in subject_list_no_space:
                if d[:2] == "CN":
                    cn = d[3:]
                    return cn
        return None
#        else:
#            temp_file_name = self.temp_path+"/temppeercert_%d" % random.randint(0,100000)
#            temp_file = open(temp_file_name,"w")
#            temp_file.write(pem_cert)
#            temp_file.flush()
#            temp_file.close()
#            print("wrote pem cert: \n" + pem_cert+"\n to file:\n"+temp_file_name)
#            m2_cert_obj = M2Crypto.X509.load_cert(temp_file_name)
#            m2_cert_as_text = m2_cert_obj.as_text()
#            print("certificate:"+m2_cert_as_text )
#            #because m2_cert_obj.get_subject().as_text() gvies error try this:
#            print("before gettin cert as text")
#            trimmed_beginning = m2_cert_as_text[m2_cert_as_text.find("CN=")+len("CN="):]
#            result = trimmed_beginning[:trimmed_beginning.find("\n")]
#            print("result="+result)
#            return result
#            #os.remove(temp_file_name)
#        
#        
#        return None
    
    """
    Parse a der encoded x509 certficate, extract the public key in the 
    certficate, and return it as a PEM encoded string
    @param der_cert: der encoded certficate
    """
    
    def get_pk_pem_string_from_der_cert(self,der_cert):
        #normally if thing would work this could be done:
        # M2Crypto.X509.load_cert_string(pem_cert_string).get_pubkey().get_rsa()
        # unfortunately this causes core dumps, so we have to take a detour via tlslite
        x509_2 = tlslite.X509.X509()
        x509_2.parseBinary(der_cert)
        pk =  x509_2.publicKey
        pem_pk_string = pk.write()
        return pem_pk_string

    """
    Get a public key object from a der encoded certficate
    @param der_cert: der encoded certficate
    """
    
    def get_pk_obj_from_der_cert_tls(self, der_cert):
        x509_2 = tlslite.X509.X509()
        x509_2.parseBinary(der_cert)
        return x509_2.publicKey
    
    
    """
    Get a public key object from a der encoded certficate
    @param der_cert: der encoded certficate
    """
    
    def get_pk_obj_from_der_cert(self, der_cert):
        pem_pk_string = self.get_pk_pem_string_from_der_cert(der_cert)
        bio = BIO.MemoryBuffer(pem_pk_string)
        fromMemLoadedPubKey = M2Crypto.RSA.load_pub_key_bio(bio)
    
    """
    Parse a der encoded certficate string to certficate object
    @param der_cert_string: der encoded certficate
    """
    
    def parseDERCert_tls(self,der_cert_string):
        x509_2 = tlslite.X509.X509()
        x509_2.parseBinary(der_cert_string)
        return x509_2
    
    """
    Parse a der encoded certficate string to certficate object
    @param der_cert_string: der encoded certficate
    """ 
    
    def parseDERCert(self,der_cert_string):
        pem_cert_string = der_2_pem_cert(der_cert_string)
        m2_cert_obj = M2Crypto.X509.load_cert_string(pem_cert_string)
        return m2_cert_obj       
            
    """
    Convert a der encoded certficate string to a pem encoded certificate string
    @param der_cert_string: der encoded certficate
    """
    
    def der_2_pem_cert(self,der_cert_string):
        pem_cert_string = "-----BEGIN CERTIFICATE-----\n" + self.der_2_pem(der_cert_string)+"-----END CERTIFICATE-----\n"
        return pem_cert_string
    
    
    """
    Convert a der encoded string to a pem encoded  string without start/end lines indicating start/end of key or certficate
    @param der_cert_string: der encoded certficate
    """
    
    def der_2_pem(self, der_cert_string):
        base64.MAXLINESIZE = 64 
        base64.MAXBINSIZE = (base64.MAXLINESIZE//4)*3
        return base64.encodestring(der_cert_string)
    
    
    """
    Validate a certficate (object) with the pem files from self.ca_dir
    @param certificate: certficate object to validate 
    """
    
    def validate_in_mem_certificate(self,certificate):          
        temp_file_name = self.temp_path+"/temppeercert_%d" % random.randint(0,100000)
        temp_file = open(temp_file_name,"w")
        print "len of pubkey in cert = %d" % (len(certificate.publicKey))
        der_string = certificate.writeBytes()
        pem_string =  self.der_2_pem_cert(der_string)
        temp_file.write(pem_string)
        temp_file.flush()
        temp_file.close()
        result = self.validate_certificate(temp_file_name)
        #os.remove(temp_file_name)
        return result

    """
    Validate a certficate file with the pem files from self.ca_dir
    @param certificate: location of certficate file to validate 
    """
    
    
    
    def validate_certificate(self,certificate):
           
        command = "openssl verify -CAfile "+self.ca_path+"  "+certificate
        print " command= %s" % command
        result = commands.getstatusoutput(command)
        print "result is " +str(result)
        if(result[0] == 0): print "ssl verify terminated succefully"
        if(re.match(".*OK", result[1]) and not re.match(".*error.*", result[1])): 
            return True
        else:
            return False
        
    """
    Convert an openssl public key object to an m2crypto public key object (different implementations)
    @param pycrypto_key: pycrypto key to convert
    @return: m2public key corresponding to argument
    """
    
    
    def openSSL_2_m2public_key(self, pycrypto_pubkey):
        temp_file_name = self.temp_path+"/temppubkey_%d" % random.randint(0,100000)
        temp_file = open(temp_file_name,"w")
        temp_file.write(pycrypto_pubkey.write())
        temp_file.close()
        m2pubkey = M2Crypto.RSA.load_pub_key(temp_file_name)
        os.remove(temp_file_name)
        return m2pubkey
    
    
    """
    Get signature (first hash, then private key encryption) of string
    @param tlsprivkey: private key to encrypt with
    @param plaintext: plaintext to sign
    @return: string of hashed and encrypted plaintext
    """
    
    def get_sha_signature_tls(self,tlsprivkey, plaintext):
        hash = shalib.sha(plaintext).digest()
        return self.get_signature_tls(tlsprivkey, hash)
    
    """
    Check if signature (hash+private key encryption) is valid
    @param tlspubkey: public key of the signer
    @param sig:     signature to check
    @param plaintext: plaintext that is signed with sig
    @return: boolean indicating if signature is valid
    """
    
    
    def check_sha_signature_tls(self,tlspubkey,sig,plaintext):
        hash = shalib.sha(plaintext).digest()
        return self.check_signature_tls(tlspubkey,sig,hash)
        
    """
    Get signature (private key encryption, no hash) of string
    @param tlsprivkey: private key to encrypt with
    @param plaintext: plaintext to sign
    @return: string of encrypted plaintext
    """
    
    def get_signature_tls(self,tlsprivkey, plaintext):
        #while 1:
            plaintextarray = array.array('B',"")
            plaintextarray.fromstring(plaintext)
            sig = tlsprivkey.sign(plaintextarray)
            print "ptextlen = %d siglen= %d" %(len(plaintext), len(sig))
            #sometimes the len of sig != len of key, this shouldnt happen!!!
            return sig.tostring()

    """
    Check if signature (private key encryption, no hash) is valid
    @param tlspubkey: public key of the signer
    @param sig:     signature to check
    @param plaintext: plaintext that is signed with sig
    @return: boolean indicating if signature is valid
    """


    def check_signature_tls(self,tlspubkey,sig,ptext):
        sigarray = array.array('B',"")
        sigarray.fromstring(sig)
        ptextarray = array.array('B',"")
        ptextarray.fromstring(ptext)
        try:
            result = tlspubkey.verify(sigarray,ptextarray)
            return result
        except:
            return False
        
    """
    Get signature (first hash, then private key encryption) of string
    @param tlsprivkey: private key to encrypt with
    @param plaintext: plaintext to sign
    @return: string of hashed and encrypted plaintext
    """
    
    
    def get_sha_signature(self,m2privkey,plaintext):
        #plaintext = zeropad(plaintext,m2privkey)
        hash = shalib.sha(plaintext).digest()
        print("in get sig: hash is : %s" % hash.encode('hex'))
        paddedhash = self.zeropad(hash,m2privkey)
        #print "length of plaintext: %d" % len(plaintext)
        sig = self._encrypt_piece(m2privkey, paddedhash,"private_encrypt",M2Crypto.RSA.no_padding)
        return sig
    
    """
    Get signature (private key encryption, no hash) of string
    @param tlsprivkey: private key to encrypt with
    @param plaintext: plaintext to sign
    @return: string of encrypted plaintext
    """
    
    
    def check_sha_signature(self,m2pubkey,sig,ptext):
        hash = shalib.sha(ptext).digest()
        decrypted_zero_padded_hash = public_decrypt_zeropad_piece(m2pubkey, sig)
        decrypted_hash = hash[0:shalib.digestsize]
        print("in checksig dechash= %s" % decrypted_hash)
        return decrypted_hash == hash
    
    
    """ encrypt string with pkcs1 padding """
    def public_encrypt_pkcs1_padded(self,m2pubkey, plaintext):
        return self._public_encrypt_piece(m2pubkey, plaintext,M2Crypto.RSA.pkcs1_padding) 
    
    """ encrypt string with pkcs1 padding"""
    def public_encrypt_pkcs1_padded_tls(self,tlspubkey, plaintext):        
        return self._public_encrypt_piece_tls(tlspubkey, plaintext,M2Crypto.RSA.pkcs1_padding) 
    
    """ encrypt string with zero padding, for signatures"""
    def public_encrypt_zero_padded(self,m2pubkey, plaintext):
        plaintext = self.zeropad(plaintext,m2pubkey)    
        return self._public_encrypt_piece(m2pubkey, plaintext,M2Crypto.RSA.no_padding) 
     
    """ pad string with zeros to match key length """
    def zeropad(self,plaintext, encryptionkey):
        remainder = len(plaintext) % len(encryptionkey) 
        if(remainder != 0):
            padlen = len(encryptionkey) - remainder
            padding = array.array('B',[0x00]*padlen).tostring()
            plaintext+=padding 
        return plaintext
         
    def _public_encrypt_piece(self,m2pubkey, plaintext,padding_type):
        encryption_method = "public_encrypt"
        return self._encrypt_piece(m2pubkey, plaintext,encryption_method,padding_type)
    
    def _public_encrypt_piece_tls(self,tlspubkey, plaintext):
        encryption_method = "public_encrypt"
        return self._encrypt_piece(m2pubkey, plaintext,encryption_method,padding_type)
    
    """encrypts string of any length with the public key"""
    def encrypt_piece_tls(self,tls2pubkey, plaintext):
        keylen_bits = len(tls2pubkey)
        keylen_bytes = keylen_bits/8
        min_padlen = 11
        max_plaintext_block_len = keylen_bytes - min_padlen
        plaintext_array = array.array('B',[])
        cyphertext_array = array.array('B',[])
        plaintext_array.fromstring(plaintext)
        
        for i in range(0,len(plaintext_array)/max_plaintext_block_len):
    #        print "encrypting block %d" % i
            ptextblock = plaintext_array[i*max_plaintext_block_len:i*max_plaintext_block_len+max_plaintext_block_len]
    #        print "length of plaintext block: %d" % len(ptextblock) 
            ctextblock = tls2pubkey.encrypt(ptextblock)
            while len(ctextblock) != keylen_bytes:
                #somekind of bug or hardware fault? leading to 127byte ctextblocks..
                "bad ctext length: %d :retrying" % len(ctextblock)
                ctextblock = tls2pubkey.encrypt(ptextblock)
                "retry ctext length: %d " % len(ctextblock)
            print "length ctextblock %d  = %d" % (i,len(ctextblock))
            cyphertext_array+=ctextblock
            
        lastlen = (len(plaintext_array) % max_plaintext_block_len)
        if lastlen != 0:
            ptextblock = plaintext_array[-lastlen:]
            #print "length last block %d max_blocklen= %d, end offset %d " % (len(ptextblock),max_plaintext_block_len,-(len(plaintext_array) % max_plaintext_block_len))
            while 1: 
                 ctextblock = tls2pubkey.encrypt(ptextblock)
                 if len(ctextblock) == 128:
                     break
            cyphertext_array+=ctextblock
            print "length last ctextblock = %d" % len(ctextblock)
        
        return cyphertext_array.tostring()
    
    
    
    
    def _encrypt_piece(self,m2pubkey, plaintext,encryption_method,padding_type):
        """encrypts string of any length with the public key"""
        print "encryption method is: " + encryption_method
        keylen_bits = len(m2pubkey)
        keylen_bytes = keylen_bits/8
        min_padlen = 0
        if padding_type == M2Crypto.RSA.pkcs1_padding: min_padlen = 11
        if padding_type == M2Crypto.RSA.no_padding: min_padlen = 0
        max_plaintext_block_len = keylen_bytes - min_padlen
        plaintext_array = array.array('B',[])
        cyphertext = ""
        plaintext_array.fromstring(plaintext)
        encryption_method = getattr(m2pubkey,encryption_method)
        
        for i in range(0,len(plaintext_array)/max_plaintext_block_len):
    #        print "encrypting block %d" % i
            ptextblock = plaintext_array[i*max_plaintext_block_len:i*max_plaintext_block_len+max_plaintext_block_len]
    #        print "length of plaintext block: %d" % len(ptextblock) 
            ctextblock = encryption_method(ptextblock,padding_type)
            cyphertext+=ctextblock
            
        lastlen = (len(plaintext_array) % max_plaintext_block_len)
        if lastlen != 0:
            ptextblock = plaintext_array[-lastlen:]
    #        print "length last block %d max_blocklen= %d, end offset %d " % (len(ptextblock),max_plaintext_block_len,-(len(plaintext_array) % max_plaintext_block_len))
            ctextblock = encryption_method(ptextblock,padding_type)
            cyphertext+=ctextblock
        
        return cyphertext
    
    def public_decrypt_pkcs1pad_piece(self,m2privkey, cyphertext):
            return self._decrypt_piece(m2privkey, cyphertext,"public_decrypt",M2Crypto.RSA.pkcs1_padding)
    
    def public_decrypt_zeropad_piece(self,m2privkey, cyphertext):
            return self._decrypt_piece(m2privkey, cyphertext,"public_decrypt",M2Crypto.RSA.no_padding)    
        
    def private_decrypt_pkcs1pad_piece(self,m2privkey ,ctext):
        return self._decrypt_piece(m2privkey, ctext,"private_decrypt",M2Crypto.RSA.pkcs1_padding)
    
    def _decrypt_piece(self,m2privkey, cyphertext,decryption_method,padding_type):
        """decrypts rsa encoded multi block strings with pkcs1 padding"""
        keylen_bits = len(m2privkey)
        keylen_bytes = keylen_bits/8
        ptext = ""
        decryption_method = getattr(m2privkey,decryption_method)
        cyphertext_array = array.array('B',[])
        cyphertext_array.fromstring(cyphertext)
        for i in range(0,len(cyphertext_array)/keylen_bytes):
            ctextblock = cyphertext_array[i*keylen_bytes:i*keylen_bytes+keylen_bytes]
            ptextblock = decryption_method(ctextblock,padding_type)
            ptext += ptextblock
        if(len(cyphertext_array) % keylen_bytes != 0):
            print "error ctext len not multiple of blocklen ctext = %d, blocklen= %d" % (len(cyphertext_array),keylen_bytes) 
            
        return ptext
    
    """decrypts rsa encoded multi block strings with pkcs1 padding"""
    def decrypt_piece_tls(self, tlsprivkey, cyphertext):
        keylen_bits = len(tlsprivkey)
        keylen_bytes = keylen_bits/8
        plaintextarray =  array.array('B',[])
        cyphertext_array = array.array('B',[])
        cyphertext_array.fromstring(cyphertext)
        print "before for in decrypt piece, len ctextarray = %d" % len(cyphertext_array)
        for i in range(0,len(cyphertext_array)/keylen_bytes):
            print "decrypting %d-th block" % i
            ctextblock = cyphertext_array[i*keylen_bytes:i*keylen_bytes+keylen_bytes]
            #print "decrypting block number %d, len %d, value %s" % (i,len(ctextblock),ctextblock)
            ptextblock = tlsprivkey.decrypt(ctextblock)
            if ptextblock:
                print "ptextblock = %s" %  ptextblock.tostring()
                plaintextarray += ptextblock
            else:
                teststring =  "decrypt error".join(["%d" % a for a in range(1,1000)] )
                print "ptextblock = none"
                print "teststring = %s" % teststring
            
        if(len(cyphertext_array) % keylen_bytes != 0):
            print "error ctext len not multiple of blocklen ctext = %d, blocklen= %d" % (len(cyphertext_array),keylen_bytes) 
        
        return plaintextarray.tostring()
 
def parse_PEM_certificate(file):
    return tlslite.X509.X509().parse(file.read())

def parse_PEM_private_key(file):
    return tlslite.utils.keyfactory.parsePEMKey(file.read())
    
    
if __name__ == "__main__":
        pktools = PKTools("/home/erik/vu/thesis/erixca-cacert.pem")
        piece_count = 10000
        payment_keys = []
        for key_num in range(0,piece_count):
             payment_keys.append( "%020d" % key_num)
        privkey = "/home/erik/vu/thesis/pikachu2.key"
        privkey = open(privkey).read()
        privkey = parsePEMKey(privkey)
        cert =  "/home/erik/vu/thesis/pikachu2-cert.pem"
        cert = open(cert).read()
        import tlslite
        cert = tlslite.X509.X509().parse(cert)
        pubkey = cert.publicKey
        
        #encrypt
        ptextstring = "".join(payment_keys)
        #ptextstring = "geheim"
        ptext = array.array('B')
        ptext.fromstring(ptextstring)
        ctext = pktools.encrypt_piece_tls(pubkey, ptext)
        print "ctext "+ ctext.encode('hex')
        print "len ctext = %d" % len(ctext)
        
        
        #decrypt
        
        dectext = pktools.decrypt_piece_tls(privkey, ctext)
        
        print "dectext\n\n"+dectext
        
    