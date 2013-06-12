# WebID+TLS authentication library for _Erlang_
This library implements the [WebID+TLS](https://dvcs.w3.org/hg/WebID/raw-file/tip/spec/tls-respec.html) authentication protocol using the [raptor bindings](https://github.com/jonasp/erlang-raptor) for Erlang.

## warning
This software is at a very early alpha stage.
The raptor bindings used are unfinished and might crash the ErlangVM. 

## build
1. get dependencies ``./rebar get-deps``
2. compile ``./rebar compile``

At the moment the example needs to be compiled manually and the certificates need to be in the correct place.  
1. ``cd ebin``  
2. ``erlc ../examples/src/webid_example.erl``  
3. ``cp -r ../examples/certs .``  

## usage
start and stop application as usual
```erlang
application:start(webid).
application:stop(webid).
```

verify WebID aware certificates
```erlang
{ok, Cert} = ssl:peercert(AcceptedSock),
DecodedCert = public_key:pkix_decode_cert(Cert, plain),
webid:verify(DecodedCert) -> {ok, WebID}
			              -> {error, eauthfailed}
```

## License
This software is licensed under the Apache License Version 2.0.  
See http://www.apache.org/licenses/LICENSE-2.0 or the LICENSE file.

Copyright (C) 2013 Jonas Pollok
