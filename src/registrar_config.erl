%%%-----------------------------------------------------------------------------
%%% @copyright (C) 2023, 2600Hz
%%% @doc
%%% This Source Code Form is subject to the terms of the Mozilla Public
%%% License, v. 2.0. If a copy of the MPL was not distributed with this
%%% file, You can obtain one at https://mozilla.org/MPL/2.0/.
%%%
%%% @end
%%%-----------------------------------------------------------------------------
-module(registrar_config).

-export([listeners/0, listeners/1, set_listeners/1]).

-include("reg.hrl").

-spec listeners() -> non_neg_integer().
listeners() ->
    listeners(10).

-spec listeners(non_neg_integer()) -> non_neg_integer().
listeners(Count) ->
    kapps_config:get_integer(?CONFIG_CAT, <<"listeners">>, Count).

-spec set_listeners(non_neg_integer()) -> non_neg_integer().
set_listeners(Count) ->
    _ = kapps_config:set_default(?CONFIG_CAT, <<"listeners">>, Count),
    Count.
