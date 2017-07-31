%% ------------------------------------------------------------------
%% @author Christian Flodihn <christian@flodhn.se>
%% @copyright G-bits
%% @doc
%% @end
%% ------------------------------------------------------------------
-module(elogin_router).
-export([handle/2, handle_event/3]).

-include_lib("elli/include/elli.hrl").

handle(Req, _Args) ->
    %% Delegate to our handler function
    elogin_util:validate_ip(Req) orelse throw({403, [], <<"Forbidden">>}),
    handle(Req#req.method, elli_request:path(Req), Req).

handle(Method, [<<"api">>, <<"accounts">> | _Rest] = Path, Req) ->
    require_auth_or_redirect_to_login(Req),
    elogin_accounts:handle(Method, Path, Req);

%% jquery-ui images
handle(_Method, [<<"images">>, Image], _Req) ->
    ImageData = elogin_util:read_raw_file(
            "images/" ++ binary_to_list(Image)),
    {200, [], ImageData};

%% HTML files
handle('GET', [<<"jquery.js">>], _Req) ->
    File = elogin_util:read_raw_file("jquery.js"),
    {200, [], File};

handle('GET', [<<"jquery-ui.js">>], _Req) ->
    File = elogin_util:read_raw_file("jquery-ui.js"),
    {200, [], File};

handle('GET', [<<"jquery-ui.css">>], _Req) ->
    File = elogin_util:read_raw_file("jquery-ui.css"),
    {200, [], File};

handle('GET', [<<"style.css">>], _Req) ->
    File = elogin_util:read_raw_file("style.css"),
    {200, [], File};

handle('GET', [<<"ds_functions.js">>], _Req) ->
    File = elogin_util:read_raw_file("ds_functions.js"),
    {200, [], File};

handle('GET', [<<"ds_ui.js">>], _Req) ->
    File = elogin_util:read_raw_file("ds_ui.js"),
    {200, [], File};

handle('GET', [<<"jquery.base64.min.js">>], _Req) ->
    File = elogin_util:read_raw_file("jquery.base64.min.js"),
    {200, [], File};

%% Dragula jquery plugin
handle('GET', [<<"dragula.min.js">>], _Req) ->
    File = elogin_util:read_raw_file("dragula.min.js"),
    {200, [], File};

handle('GET', [<<"dragula.min.css">>], _Req) ->
    File = elogin_util:read_raw_file("dragula.min.css"),
    {200, [], File};

handle('GET', [<<"custombox.min.css">>], _Req) ->
    File = elogin_util:read_raw_file("custombox.min.css"),
    {200, [], File};

handle('GET', [<<"custombox.min.js">>], _Req) ->
    File = elogin_util:read_raw_file("custombox.min.js"),
    {200, [], File};

handle('GET',[], Req) ->
    case elogin_util:require_auth(Req) of
        true ->
            LoginHtml= elogin_util:read_raw_file("login.html"),
            {200, [], LoginHtml};
        false ->
            Header = elogin_util:read_html_header(),
            Footer = elogin_util:read_html_footer(),
            {200, [], <<Header/binary, Footer/binary>>}
    end;

handle('GET', [<<"ping">>], _Req) ->
    {200, [], <<"pong">>};

handle('GET', [<<"cwd">>], _Req) ->
    {ok, Cwd} = file:get_cwd(),
    {200, [], list_to_binary(Cwd)};

handle('GET', [<<"accounts">>], Req) ->
    require_auth_or_redirect_to_login(Req),
    Html = elogin_util:read_html_file(<<"accounts.html">>),
    {200, [], Html};

handle(_, _, _Req) ->
    {404, [], <<"Not Found">>}.

%% @doc: Handle request events, like request completed, exception
%% thrown, client timeout, etc. Must return ok.
handle_event(_Event, _Data, _Args) ->
    ok.

require_auth_or_redirect_to_login(Req) ->
    Html = elogin_util:redirect_html(
        "/login", "Authorization Required", 1, Req), 
    elogin_util:require_auth(Req) andalso throw(
        {200, [], Html}).
