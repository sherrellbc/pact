#!/usr/bin/python3

#import ssl
import time
import hashlib
import zlib
import sys
import struct
import argparse
import logging
from enum import IntEnum

class PactType(IntEnum):
    SIGN_CUSTOM0 =      0
    SIGN_CUSTOM1 =      1,

class PactRequest:
    REQUEST_MAGIC = bytes('PTRQ', 'utf-8')

    def __init__(self, sock, req_type=None, data=None, compress=False):
        # We must support initialization without a known type because,
        # unlike the client use-case, the server does not aprori know the
        # type to be handled; it must first receive the request
        if(None != req_type):
            if(False == PactRequest.__check_type__(req_type)):
                raise Exception('Invalid input: req_type=' + str(req_type))

        if(None == sock):
            raise Exception('Invalid input: sock=None') 

        self.sock = sock
        self.req = None
        self.compress = compress

        # Components of a request
        self.magic = None
        self.req_type = req_type
        self.data_len = None
        self.hash = None
        self.data = data
        self.crc32 = None

    def set_type(self, req_type):
        if(True == PactRequest.__check_type__(req_type)):
            self.req_type = req_type
        # else ... exception?

    @staticmethod
    def __check_type__(req_type):
        if( (req_type >= len(PactType)) or
            (req_type < 0) ):
            return False
        return True

    # Offset	Length	Content
    # -------------------------
    # 0x00	4	Magic 			(PactRequest.REQUEST_MAGIC)
    # 0x04	4	Request type 	(PactType)
    # 0x08	4	Length of uncompressed payload
    # 0x0c	4	Length of compressed payload
    # 0x10	32	Hash of payload
    # 0x30		Variable length compressed payload
    # xxxx      4       CRC32
    def __construct_request__(self):
        self.hash = hashlib.sha256()
        self.hash.update(self.data)
        self.hash = self.hash.digest()

        cdata_len = 0
        data = self.data
        if(True == self.compress):
            stime = time.time()
            logging.debug('Compressing payload ...')
            data = zlib.compress(self.data, zlib.Z_BEST_COMPRESSION)
            cdata_len = len(data)
            logging.debug('Compressed infile in {:.2f}s. {} -> {}, Ratio: {:.2f}'
                .format(time.time() - stime, len(self.data), cdata_len, cdata_len/len(self.data)))

        self.req  = struct.pack('!4s', PactRequest.REQUEST_MAGIC)
        self.req += struct.pack('!I', self.req_type) 
        self.req += struct.pack('!I', len(self.data))   # Uncompessed len
        self.req += struct.pack('!I', cdata_len)        # Compressed len, otherwise 0
        self.req += struct.pack('!32s', self.hash)
        self.req += data 
        self.req += struct.pack('!I', zlib.crc32(self.req))

    # See __prepend_header_ above
    def __recv_header__(self):
        self.header = self.sock.recv(4 + 4 + 4 + 4 + 32)
        if(b'' == self.header):
            raise Exception('Failed to recv header from remote')

        self.magic =        struct.unpack_from('!4s',  self.header, offset=0x00)[0]
        self.req_type =     struct.unpack_from('!I',   self.header, offset=0x04)[0]
        self.data_len =     struct.unpack_from('!I',   self.header, offset=0x08)[0]
        self.cdata_len =    struct.unpack_from('!I',   self.header, offset=0x0c)[0]
        self.hash =         struct.unpack_from('!32s', self.header, offset=0x10)[0]

    # Magic
    # Checksum (Uses compressed data contents, if applicable)
    # Uncompressed len (If data is compressed)
    # Hash
    def __check_integrity__(self):
        if(PactRequest.REQUEST_MAGIC != self.magic):
            logging.debug('Request had wrong magic') 
            return False

        if(self.crc32 != zlib.crc32(self.header + self.data)):
            logging.debug('Request had bad checksum')
            return False

        # Decompress _after_ checking CRC of compressed payload 
        if(0 != self.cdata_len):
            self.data = zlib.decompress(self.data)
        if(self.data_len != len(self.data)):
            logging.debug('Request had bad uncompressed length') 
            return False

        # Check _after_ decompressing a compressed payload
        check_hash = hashlib.sha256()
        check_hash.update(self.data)
        if(self.hash != check_hash.digest()):
            logging.debug('Request had bad hash')
            return False

        return True

    def set_data(self, data):
        self.data = data

    # Common send/recv implementations
    def send(self):
        total = 0
        self.__construct_request__()

        while(total != len(self.req)):
            chunk = self.sock.send(self.req[total:])
            if(0 == chunk):
                raise Exception('Failed to send to remote')
            total += chunk

    def recv(self):
        try:
            self.__recv_header__() 

            # Compressed length is zero if data is uncompressed
            data_len = self.cdata_len
            if(0 == self.cdata_len):
                data_len = self.data_len 

            data_len += 4   # +4 for CRC32
            self.data = b''
            while(len(self.data) != data_len):
                chunk = self.sock.recv(min(data_len - len(self.data), 2**16))
                if(b'' == chunk):
                    raise Exception('Failed to recv payload from remote')
                self.data += chunk
        except:
           raise

        # Lop off the crc32 at the tailend of the payload
        self.crc32 = struct.unpack('!I', self.data[-4:])[0]
        self.data = self.data[:-4]

        # Check the integrity of the message
        if(True == self.__check_integrity__()):
            return (self.data, self.req_type)

        raise Exception('Integrity check failed on recv request')

if('__main__' == __name__):
    from pact_server import PactServer
    from pact_client import PactClient

    parser = argparse.ArgumentParser()
    parser.add_argument('-l',
                        dest='logfile',
                        default=None,
                        help='Location of logfile')

    parser.add_argument('-v',
                        dest='verbose',
                        default=False,
                        action='store_true',
                        help='Log extra debugging information')
    
    parser.add_argument('-c',
                        dest='compress',
                        default=False,
                        action='store_true',
                        help='Compress transfers') 

    parser.add_argument('-i',
                        dest='infile',
                        default=None,
                        help='[Client] Input file to sign')

    parser.add_argument('-o',
                        dest='outfile',
                        default=None,
                        help='[Client] Output signed file (Default: infile.signed)')

    parser.add_argument('-t',
                        dest='type',
                        default=PactType.SIGN_CUSTOM0,
                        type=int,	
                        help='[Client] Signature type')

    parser.add_argument('-k',
                        dest='key',
                        default=None,
                        help='[Server] Keyfile used for signing') 

    parser.add_argument('-s',
                        dest='server',
                        default=False,
                        action='store_true',
                        help='[Server] Start the signing server')

    parser.add_argument('remote:port',
                        help='[Server] Local binding / [Client] Remote')

    args = parser.parse_args()
    creds = vars(args)['remote:port'].split(':')

    # Sanity check for required input args
    if(True == args.server):
        if(None == args.key):
            logging.error('Invocation as server requires key')
            sys.exit(1)
    else:
        if(None == args.infile):
            logging.error('Invocation as client requires infile')
            sys.exit(1)

        if(None == args.type):
            logging.error('Invocation as client requires type')
            sys.exit(1)

        if(None == args.outfile):
            args.outfile = args.infile + '.signed'

    # Initialize logging
    level = logging.INFO
    if(True == args.verbose):
        level = logging.DEBUG	
    logging.basicConfig(format='[%(levelname)7s] %(message)s',
            filename=args.logfile, level=level)
    
    # Start client or server 
    if(True == args.server):
        ps = PactServer(creds[0], int(creds[1]), vars(args))
        ps.do_serve()
    else:
        pc = PactClient(creds[0], int(creds[1]), vars(args))
        pc.do_request()	
