Overview
--------
Pact is a simple client/server tool that allows remote usage of
protected key information. The current implementation was designed to
receive binary blobs that will be returned to remote clients after appending
signature information using a local (to the server) private key. In this way
the sensitive key information need not be exposed to users.


Using Pact
----------
Start the server

```
$ ./pact.py -sk/tmp/cert.pem 0.0.0.0:5000
[   INFO] Server listening on port 5000
[   INFO] [   0] Handled type:0 request from ('127.0.0.1', 59680); len:1113504 in 0.04s
```

Issue a signing request from a client

```
$ ./pact.py -i`which bash` -o/tmp/bash.signed -t0 localhost:5000
[   INFO] Sending signing request ...
[   INFO] Waiting for response ...
[   INFO] Writing outfile '/tmp/bash.signed' with length: 1113507
```

The resulting signed file will be saved to the location specified by -o. If
no output file is specified then the signed result will be found in the same
directory as the input file with a name appended with '.signed'

Note that with client requests one must also supply the `-t` option for
specifiying a signaturing type. See `PactType` and `PactServer.sign` for
details. Augmenting the server with additional signing types can be
accomplished by simply adding a new type, method implementation, and appending
the new function pointer to the list in `PactServer.sign`.

For large signing requests the `-c` option may be used to compress payload
data before sending. This option may also be used on the server if compression
is to be used for transfer of response messages regardless of client configuration.

Notes
-----
* See `./pact.y -h` for help
* The `pact.py` module is used to start both client and server
* See `PactServer.sign` for signaturing implementations


Future
------
* SSL for transfers
* Support multiple keys
* Server should compress response if client send compressed request
