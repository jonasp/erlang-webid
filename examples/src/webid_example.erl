% Licensed under the Apache License, Version 2.0 (the "License"); you may not
% use this file except in compliance with the License. You may obtain a copy of
% the License at
%
%   http://www.apache.org/licenses/LICENSE-2.0
%
% Unless required by applicable law or agreed to in writing, software
% distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
% WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
% License for the specific language governing permissions and limitations under
% the License.

%%% Purpose: Test if the FOAF+SSL Authentication library is working

-module(webid_example).

-export([start/0, init/1]).

-export([mk_opts/1]).

start() ->
    application:start(crypto),
    application:start(public_key),
    application:start(ssl),
	application:start(webid),

    {ok, ListenSock} = ssl:listen(0, mk_opts(listen)),
    {ok, {_, ListenPort}} = ssl:sockname(ListenSock),

    spawn(?MODULE, init, [ListenPort]),

    {ok, AcceptedSock} = ssl:transport_accept(ListenSock),
    ok = ssl:ssl_accept(AcceptedSock),
    io:fwrite("Accept: accepted.~n"),

    %% Get the client certificate from Socket
	{ok, Cert} = ssl:peercert(AcceptedSock),

    %% Verify user with the client certificate
	{ok, WebID} = webid:verify(public_key:pkix_decode_cert(Cert, plain)),
	io:fwrite("Verified WebID: ~p~n", [WebID]),

    %ssl:send(AcceptedSock, "Hello "++WebID),
    ssl:send(AcceptedSock, "Hello World"),

    ssl:close(AcceptedSock),
    ssl:close(ListenSock),
	application:stop(webid),
    application:stop(ssl),
    application:stop(public_key),
    application:stop(crypto).

%% Client connect
init(ListenPort) ->
    {ok, Hostname} = inet:gethostname(),
    {ok, ConnectSock} = ssl:connect(Hostname, ListenPort, mk_opts(connect)),
    {ok, Data} = ssl:recv(ConnectSock, 0),
    io:fwrite("Data received: ~p~n", [Data]),
    ssl:close(ConnectSock).

mk_opts(listen) ->
	Dir = filename:join([code:lib_dir(ssl), "examples", "certs", "etc"]),
	[{active, false},
	 {verify, verify_peer},
	 {verify_fun,
		%{fun(_, {bad_cert, selfsigned_peer}, UserState) ->
		{fun(_, {bad_cert, unknown_ca}, UserState) ->
					{valid, UserState};
				(_,{bad_cert, selfsigned_peer}, UserState) ->
					{valid, UserState};
				(_,{bad_cert, _} = Reason, _) ->
					{fail, Reason};
				(_,{extension, _}, UserState) ->
					{unknown, UserState};
				(_, valid, UserState) ->
					{valid, UserState};
				(_, valid_peer, UserState) ->
					{valid, UserState}
			end, []}
	 },
	 {fail_if_no_peer_cert, false},
	 {depth, 1},
	 {cacertfile, filename:join([Dir, "server", "cacerts.pem"])},
	 {certfile, filename:join([Dir, "server", "cert.pem"])},
	 {keyfile, filename:join([Dir, "server", "key.pem"])}];
mk_opts(connect) ->
	Dir = filename:join([code:lib_dir(ssl), "examples", "certs", "etc"]),
	[{active, false}, 
     {verify, verify_peer},
	 {verify_fun,
		{fun(_,{bad_cert, _}, UserState) ->
					{valid, UserState};
				(_,{extension, _}, UserState) ->
					{unknown, UserState};
				(_, valid, UserState) ->
					{valid, UserState};
				(_, valid_peer, UserState) ->
					{valid, UserState}
			end, []}
	 },
	 {fail_if_no_peer_cert, false},
     {depth, 1},
	 {cacertfile, filename:join([Dir, "server", "cacerts.pem"])},
     {certfile, "certs/webid_pub.pem"},
     {keyfile, "certs/webid_key.pem"}].
