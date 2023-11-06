%%%-----------------------------------------------------------------------------
%%% @copyright (C) 2011-2023, 2600Hz
%%% @doc
%%% @author Karl Anderson
%%%
%%% This Source Code Form is subject to the terms of the Mozilla Public
%%% License, v. 2.0. If a copy of the MPL was not distributed with this
%%% file, You can obtain one at https://mozilla.org/MPL/2.0/.
%%%
%%% @end
%%%-----------------------------------------------------------------------------
-module(registrar_maintenance).

-export([device_by_ip/1]).
-export([set_listeners/1]).
-export([register_views/0]).
-export([migrate/0]).

-include("reg.hrl").

-elvis([{elvis_style, no_debug_call, disable}]).

-spec device_by_ip(kz_term:text()) -> 'ok'.
device_by_ip(IP) when not is_binary(IP) ->
    device_by_ip(kz_term:to_binary(IP));
device_by_ip(IP) ->
    io:format("Looking up IP: ~s~n", [IP]),
    case reg_route_req:lookup_account_by_ip(IP) of
        {'ok', AccountProps} ->
            pretty_print_device_by_ip(AccountProps);
        {'error', _E} ->
            io:format("Not found: ~p~n", [_E])
    end.

-spec pretty_print_device_by_ip(kz_term:proplist()) -> 'ok'.
pretty_print_device_by_ip([]) -> 'ok';
pretty_print_device_by_ip([{Key, Value}|Props]) ->
    io:format("~-39s: ~s~n", [Key, kz_term:to_binary(Value)]),
    pretty_print_device_by_ip(Props).

-spec set_listeners(integer() | binary()) -> 'ok'.
set_listeners(Count) when is_integer(Count) ->
    Count = registrar_config:set_listeners(Count),
    registrar_shared_listener_sup:set_listeners(Count);
set_listeners(Count) when is_binary(Count) ->
    set_listeners(kz_term:to_integer(Count)).

-spec register_views() -> 'ok'.
register_views() ->
    kz_datamgr:register_views_from_folder('registrar').

-spec migrate() -> 'ok'.
migrate() ->
    case registrar_config:listeners() of
        1 ->
            io:format("updating config to start 10 listeners~n", []),
            set_listeners(10);
        _Count -> 'ok'
    end.
