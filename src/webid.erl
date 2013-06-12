%% @author Jonas Pollok
%% @copyright 2013 Jonas Pollok

%% @doc gen_server responsible for the WebID verification api

-module(webid).
-author("Jonas Pollok").

-behaviour(gen_server).

%% gen_server interface
-export([start_link/0, start/0]).

%% gen_server callbacks
-export ([init/1,
	      handle_call/3,
	      handle_cast/2,
	      handle_info/2,
	      code_change/3,
	      terminate/2]).

%% API functions
-export([verify/1]).

%% server state
%-record(state, {port}).

-include_lib("public_key/include/public_key.hrl").

%% ===================================================================
%% gen_server interface 
%% ===================================================================
start_link() ->
	gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

start() ->
	gen_server:start({local, ?MODULE}, ?MODULE, [], []).

%% ===================================================================
%% gen_server callbacks
%% ===================================================================
init([]) ->
	{ok, []}.

handle_cast(_Msg, State) ->
	{noreply, State}.

%% code_change not working, implementing stub
code_change(_OldVsn, State, _Extra) ->
	{ok, State}.

handle_info(_Info, State) ->
	{noreply, State}.

terminate(_Reason, _State) ->
	ok.

handle_call(Msg, _From, State) ->
	case Msg of
		{verify, Cert} ->
			{reply, call_verify(Cert), State};
		_ ->
			{stop, undefined_messgae, State}
	end.

call_verify(Cert) ->
	{ok, 
		#'RSAPublicKey'{
			modulus = CertMod,
			publicExponent = CertExp
		}
	} = extract_pubkey_from(Cert),

	{ok, SAN} = extract_subject_alt_name_from(Cert),
	{uniformResourceIdentifier, WebID} = SAN,

	Result = raptor:parse_uri(WebID, guess),
	Keys = parse_output(Result, WebID),

	case contains(Keys, CertMod, CertExp) of
		true ->
			{ok, WebID};
		_ ->
			{error, eauthfailed}
	end.

contains(Keys, CertMod, CertExp) ->
	length(lists:filter(
			fun({
					{modulus, Mod},
					{exponent, Exp}
				}) ->
					[CertModStr] = io_lib:format("~.16B", [CertMod]),	
					[CertExpStr] = io_lib:format("~p", [CertExp]),
					(Mod == "\"" ++ CertModStr ++
						"\"^^<http://www.w3.org/2001/XMLSchema#hexBinary>") and
					(Exp == "\"" ++ CertExpStr ++
						"\"^^<http://www.w3.org/2001/XMLSchema#integer>")
			end, Keys
		)) > 0.

extract_pubkey_from(Cert) ->
	TBSCert = Cert#'Certificate'.tbsCertificate,
	SPKInfo = TBSCert#'TBSCertificate'.subjectPublicKeyInfo,
	{0, DerKey} = SPKInfo#'SubjectPublicKeyInfo'.subjectPublicKey,
	'OTP-PUB-KEY':decode('RSAPublicKey', DerKey).

extract_subject_alt_name_from(Cert) ->
	#'TBSCertificate'{extensions = Extensions} = Cert#'Certificate'.tbsCertificate,
	get_extension('OTP-PUB-KEY':'id-ce-subjectAltName'(), Extensions).

get_extension(Key, [#'Extension'{extnID = Key, extnValue = Value} | _T]) ->
  {ok, [Decoded]} = 'OTP-PUB-KEY':decode('SubjectAltName', list_to_binary(Value)),
  {ok, Decoded};
get_extension(Key, [_H | T]) ->
  get_extension(Key, T);
get_extension(_Key, []) ->
  none.

parse_output(Result, WebID) ->
	% extract key nodes where subject is WebID
	KeyNodes= lists:filter(
		fun({
				{subject,{uri, URI}},
				{predicate,{uri, "<http://www.w3.org/ns/auth/cert#key>"}},
				{object, _}
			}) -> URI == "<" ++ WebID ++ ">";
			(_) -> false
		end, Result),
	% get key entry for every key node
	KeyEntries= lists:map(
		fun({
				{subject, _},
				{predicate, _},
				{object, Object}
			}) -> 
				lists:filter(
					fun({
							{subject, Subject},
							{predicate, _},
							{object, _}
						}) -> Subject == Object 
					end, Result)
		end, KeyNodes),
	lists:map(
		fun(KeyEntry) ->
				get_key_details(KeyEntry)
		end, KeyEntries).

get_key_details(KeyEntry) ->
	get_key_details([], [], KeyEntry).

get_key_details(Mod, Exp, [H|T]) ->
	case H of
		{
			_,
			{predicate,{uri,"<http://www.w3.org/ns/auth/cert#modulus>"}},
			{object,{literal, Modulus}}
		} ->
			get_key_details(Modulus, Exp, T);
		{
			_,
			{predicate,{uri,"<http://www.w3.org/ns/auth/cert#exponent>"}},
			{object,{literal,Exponent}}
		} ->
			get_key_details(Mod, Exponent, T);
		_ ->
			get_key_details(Mod, Exp, T)
	end;
get_key_details(Mod, Exp, []) ->
	{{modulus, Mod},{exponent, Exp}}.


%% ===================================================================
%% API functions
%% ===================================================================
verify(Cert) ->
	call_server({verify, Cert}).

call_server(Msg) ->
	gen_server:call(?MODULE, Msg, get_timeout()).

get_timeout() ->
	{ok, Value} = application:get_env(webid, timeout),
	Value.
