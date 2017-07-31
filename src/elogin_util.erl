%% ------------------------------------------------------------------
%% @author Christian Flodihn <christian@flodihn.se>
%% @doc
%% @end
%% ------------------------------------------------------------------
-module(elogin_util).

-include_lib("elli/include/elli.hrl").

-define(VALID_ID_REGEXP, "^[A-Z0-9]{1,255}$").

-export([
    split_query_string/2,
	is_string_valid_json/1,
	json_string_to_dict/1,
    json_to_dict/1,
    read_raw_file/1,
    read_html_header/0,
    read_html_footer/0,
    read_html_file/1,
    validate_ip/1,
    require_auth/1,
    redirect_html/4,
    clean_post_text/1,
    validate_input_dict/2,
    get_content_type/1,
    validate_id_from_request/1,
    validate_id_from_request/2,
    validate_and_clean_id/1,
    dict_fetch_with_default/3,
    md5_hexdigest/1
    ]).

split_query_string(Key, Req) ->
    QueryArgs = dict:from_list(elli_request:get_args_decoded(Req)),
    BinList = dict_fetch_with_default(Key, QueryArgs, <<>>),
    binary:split(BinList, <<",">>, [global]).

json_to_dict({struct, PropList}) ->
    json_proplist_to_dict(PropList, dict:new()).

json_proplist_to_dict([], Acc) ->
    Acc;

json_proplist_to_dict([{Key, {array, NestedList}} | PropList], Acc) ->
    List = json_to_list(NestedList, []),
    json_proplist_to_dict(PropList, dict:store(Key, List, Acc));

json_proplist_to_dict([{Key, {struct, NestedPropList}} | PropList], Acc) ->
    NestedDict = json_proplist_to_dict(NestedPropList, dict:new()),
    json_proplist_to_dict(PropList, dict:store(Key, NestedDict, Acc));

json_proplist_to_dict({struct, PropList}, Acc) ->
    json_proplist_to_dict(PropList, Acc);

json_proplist_to_dict([{Key, Value} | PropList], Acc) ->
    json_proplist_to_dict(PropList, dict:store(Key, Value, Acc)).

json_to_list([], Acc) ->
    Acc;

json_to_list([Item | NestedList], Acc) ->
    NestedDict = json_proplist_to_dict(Item, dict:new()),
    json_to_list(NestedList, [NestedDict | Acc]).

json_string_to_dict(String) when is_binary(String) ->
     json_string_to_dict(binary_to_list(String));
 
json_string_to_dict(String) ->
    {ok, {struct, Json}} = json:decode_string(String),
    dict:from_list(Json).
 
is_string_valid_json(String) when is_binary(String) ->
is_string_valid_json(binary_to_list(String));

is_string_valid_json([]) ->
     false;

is_string_valid_json(String) ->
    case json:decode_string(String) of
        {ok, {struct, _Json}} -> true;
        {error, _} -> false
    end.


read_raw_file(Filename) ->
    {ok, Data} = file:read_file("priv/html/" ++ Filename),
    Data.

read_html_header() ->
    {ok, Data} = file:read_file("priv/html/header.html"),
    Data.

read_html_footer() ->
    {ok, Data} = file:read_file("priv/html/footer.html"),
    Data.

read_html_file(FileName) when is_binary(FileName) ->
    read_html_file(binary_to_list(FileName));

read_html_file(FileName) -> 
    {ok, Data} = file:read_file("priv/html/" ++ FileName),
    Data.

validate_ip(Req) ->
    {ok, AuthorizedIPs} = application:get_env(elogin,
                                              authorized_ips),
    {ok, {Ip, _Port}} = elli_tcp:peername(Req#req.socket),
    case lists:member(any, AuthorizedIPs) of
        true -> true;
        false -> lists:member(Ip, AuthorizedIPs)
    end.

require_auth(Req) ->
    {ok, RequireAuth} = application:get_env(elogin, require_auth),
    case RequireAuth of
        false -> 
            false;
        true ->
            Cookies = elli_cookie:parse(Req),
            Username = elli_cookie:get("username", Cookies),
            CookieAuthTicket = elli_cookie:get("auth_ticket", Cookies),
            case auth_srv:get_ticket(Username) of
                {error, not_found} ->
                    true;
                {ok, {ticket, undefined}} ->
                    true;
                {ok, {ticket, AuthSrvTicket}} ->
                    %% If the ticket provided in the cookie does not match
                    %% with the ticket in the auth_srv, this will return
                    %% false to indicate we require authorization.
                    CookieAuthTicket =/= AuthSrvTicket
            end              
    end.

redirect_html(Page, Msg, Timeout, Req) ->
    StrTimeout = integer_to_list(Timeout),
    Domain = extract_domain_from_request(Req),
    Protocol = extract_protocol_from_request(Req),
    RedirectUrl = Domain ++ "/" ++ Page,
        "<html><head><meta HTTP-EQUIV=\"REFRESH\" content=\"" ++ 
        StrTimeout ++ "; url=" ++ Protocol ++ "://" ++ RedirectUrl ++ 
        "\"></head><body>" ++ Msg ++ "</body></html>".

extract_domain_from_request(Req) ->
    Domain = elli_request:get_header(
        <<"Host">>, Req, <<"localhost:5050">>),
    binary_to_list(Domain).

extract_protocol_from_request(Req) ->
    Referer = elli_request:get_header(
        <<"Referer">>, Req, <<"https://localhost:5050">>),
    <<MaybeHttps:5/binary, _Rest/binary>> = Referer,
    case MaybeHttps of
        <<"https">> -> "https";
        _NotHttps -> "http"
    end.

clean_post_text(undefined) ->
    undefined;

clean_post_text(BinaryString) ->
    clean_post_text(binary_to_list(BinaryString), []).

clean_post_text([], Acc) ->
    list_to_binary(lists:reverse(Acc));

clean_post_text([43 | Rest], Acc) ->
    clean_post_text(Rest, lists:append(" ", Acc));

clean_post_text([Char | Rest], Acc) ->
    clean_post_text(Rest, lists:append([Char], Acc)).

validate_input_dict(Dict, no_error_on_undefined) ->
    {ok, Dict};

validate_input_dict(Dict, error_on_undefined) ->
    HasUndefinedValues = fun(Key, Value, Acc) ->
        case Value of 
            undefined -> {true, Key};
            _Other -> Acc
        end                
    end,

    case dict:fold(HasUndefinedValues, false, Dict) of
        {true, Key} ->
            {error, {key_undefined, Key}};
        false ->
            {ok, Dict}
    end.

get_content_type(Req) ->
    ContentType = elli_request:get_header(<<"Content-Type">>, Req),
    case ContentType of
        <<"multipart/form-data", _RestFormData/binary>> -> 
            form_data;
        <<"application/x-www-form-urlencoded", _RestUrlEnc/binary>> ->
            form_urlencoded;
        <<"application/resource-file", _RestFormData/binary>> -> 
            resource_file;
        _Uknown ->
            unknown
    end.

validate_id_from_request(Req) ->
    validate_id_from_request(<<"id">>, Req).

validate_id_from_request(IdField, Req) ->
    Value = elli_request:post_arg_decoded(IdField, Req, undefined),
    validate_and_clean_id(Value).

validate_and_clean_id(undefined) ->
    undefined;

validate_and_clean_id(Id) when is_binary(Id) ->
    validate_and_clean_id(binary_to_list(Id));

validate_and_clean_id(Id) when is_list(Id) ->
    UpperCaseId = string:to_upper(Id),
    case re:run(UpperCaseId, ?VALID_ID_REGEXP) of
        nomatch ->
            throw({400, [], <<"Illegal characters in id.">>});
        {match, _} ->
            BinaryUpperCaseId = list_to_binary(UpperCaseId),
            BinaryUpperCaseId
    end.

dict_fetch_with_default(Key, Dict, Default) ->
    case dict:find(Key, Dict) of
        {ok, Value} -> Value;
        error -> Default
    end.

md5_hexdigest(X) when is_binary(X) ->
    list_to_binary(string:to_upper(lists:flatten(
        [io_lib:format("~2.16.0b", [N]) || N <- binary_to_list(X)])));

md5_hexdigest(X) when is_list(X) ->
    list_to_binary(string:to_upper(lists:flatten(
        [io_lib:format("~2.16.0b", [N]) || N <- X]))).
