import socket
import struct
import logging
import sys
import time
from threading import Thread

from pact import PactRequest, PactType

class PactServer:
    def __init__(self, interface, port, args):
        self.num_served = 0
        self.interface = interface
        self.port = port
        self.compress = args['compress']
        self.key =      args['key']

        # TODO: import and cache the key

    @staticmethod
    def __handle_client__(client_id, sock, ip, compress, key):
        tstart = time.time()

        # Create a PactRequest container 
        pr = PactRequest(sock, compress=compress)

        try:
            # Recv and unpack the request
            (data, req_type) = pr.recv()

            # Execute the request
            signed_data = PactServer.sign(data, req_type, key)

            # Reuse the container to respond
            pr.set_data(signed_data)
            pr.send()
        except Exception as e:
            logging.error('[{:4d}] Failed to handle request from {}: {}'
                    .format(client_id, ip, str(e)))
            return
        finally:
            sock.close()

        logging.info('[{:4d}] Handled type:{} request from {}; len:{} in {:.2f}s'
                .format(client_id, req_type, ip, len(data), time.time() - tstart))

    # The 'key' is passed to the signing function. Each implementation
    # should itself interpret and use this information as necessary 
    @staticmethod
    def sign(data, req_type, key):
        def __sign_custom0__(data, key):
            logging.debug('Signing using: CUSTOM0')
            return data + bytes('CUSTOM0', 'utf-8')

        def __sign_custom1__(data, key):
            logging.debug('Signing using: CUSTOM1')
            return data + bytes('CUSTOM1', 'utf-8')

        return [ __sign_custom0__,
                 __sign_custom1__ ][req_type](data, key)

    def do_serve(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((self.interface, self.port))
        s.listen(5)

        logging.info('Server listening on port ' + str(self.port))
        while(1):
            try:
                sock, ip = s.accept()
            except KeyboardInterrupt: 
                break

            Thread(target=PactServer.__handle_client__, 
                args=(self.num_served, sock, ip, self.compress, self.key)).start()
            self.num_served += 1

        logging.info('Terminating signing server')
        s.close()
