-module(webid_app).
-author("Jonas Pollok").

-behaviour(application).

%% Application callbacks
-export([start/2, stop/1]).

%% ===================================================================
%% Application callbacks
%% ===================================================================

start(_StartType, _StartArgs) ->
	webid_deps:ensure(),
	ensure_started(raptor),
	webid_sup:start_link().

ensure_started(App) ->
	case application:start(App) of
		ok ->
			ok;
		{error, {already_started, App}} ->
			ok
	end.

stop(_State) ->
    ok.
