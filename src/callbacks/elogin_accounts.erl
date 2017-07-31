%% ------------------------------------------------------------------
%% @author Christian Flodihn <christian@flodihn.se>
%% @doc
%% @end
%% ------------------------------------------------------------------
-module(elogin_accounts).
-export([handle/3]).

-include_lib("elli/include/elli.hrl").

handle('GET', [<<"api">>, <<"accounts">>, <<"count">>], 
       _Req) ->
    NumAccounts = config_util:call_account_srv(count),
    {200, [], integer_to_list(NumAccounts)};

handle('POST', [<<"api">>, <<"accounts">>], _Req) ->
	{200, [], <<"OK">>}.

