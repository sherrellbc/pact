import logging
import socket
import struct
import sys

from pact import PactRequest, PactType

class PactClient:
    def __init__(self, remote, port, args):
        self.remote = remote
        self.port = port
        self.data = None
        self.signed_data = None
        self.sock = None
        self.req = None
        self.infile =   args['infile']
        self.outfile =  args['outfile']
        self.type =     args['type'] 
        self.compress = args['compress']

    def __read_infile__(self):
        try:
            with open(self.infile, 'rb') as f:
                self.data = f.read()
        except OSError as e:
            logging.error('Unable to read infile \'' + self.infile + '\': ' +
                    str(e))
            sys.exit(1)

    def __remote_connect__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
        try:
            self.sock.connect((self.remote, self.port))
        except OSError as e: 
            logging.error('Failed to connect to remote: ' + str(e))
            sys.exit(1)

    def __write_outfile__(self):
        try:
            with open(self.outfile, 'wb+') as f:
                f.truncate()
                f.write(self.signed_data)
        except OSError as e:
            logging.error('Unable to write outfile \'' + self.outfile + '\': ' +
                    str(e))
            sys.exit(1)

    def do_request(self):
        self.__read_infile__()
        logging.debug('Got infile \'' + self.infile + '\' with length: ' 
                + str(len(self.data)))

        logging.debug('Connecting to remote')
        self.__remote_connect__()

        try:
            pr = PactRequest(self.sock, self.type, self.data, self.compress)

            logging.info('Sending signing request ...')
            pr.send()

            logging.info('Waiting for response ...')
            self.signed_data = pr.recv()[0]
        except Exception as e:
            logging.error('Failed to send request or receive reply: ' + str(e))
            return
        finally:
            self.sock.close()

        logging.info('Writing outfile \'' + self.outfile + '\' with length: ' 
                + str(len(self.signed_data)))

        self.__write_outfile__()
        self.sock.close()
