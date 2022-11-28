%%%-----------------------------------------------------------------------------
%%% @copyright (C) 2023, 2600Hz
%%% @doc
%%% This Source Code Form is subject to the terms of the Mozilla Public
%%% License, v. 2.0. If a copy of the MPL was not distributed with this
%%% file, You can obtain one at https://mozilla.org/MPL/2.0/.
%%%
%%% @end
%%%-----------------------------------------------------------------------------
-module(reg_authn_req_tests).

-include_lib("eunit/include/eunit.hrl").
-include("reg.hrl").

maybe_check_emergency_address_test_() ->
    Test = fun reg_authn_req:maybe_check_emergency_address/3,

    AddrFields = [{Field, kz_binary:rand_hex(4)}
                  || Field <- [<<"caller_name">>
                              ,<<"postal_code">>
                              ,<<"street_address">>
                              ,<<"extended_address">>
                              ,<<"locality">>
                              ,<<"region">>
                              ]
                 ],
    OkNoAddr = {'ok', #auth_user{doc=device_doc('undefined')}},
    OkWithAddr = {'ok', #auth_user{doc=device_doc(kz_json:from_list(AddrFields))}},

    [{"disabled check"
     ,[?_assertMatch(OkNoAddr, Test(OkNoAddr, [], 'false'))
      ,?_assertMatch(OkWithAddr, Test(OkWithAddr, [], 'false'))
      ]
     }
    ,{"enabled check"
     ,[?_assertMatch({'error', 'missing_emergency_address'}, Test(OkNoAddr, [], 'true'))
      ,?_assertMatch(OkWithAddr, Test(OkWithAddr, [], 'true'))
      ]
     }
    ].

-spec device_doc(kz_json:object()) -> kzd_devices:doc().
device_doc(EmergencyAddress) ->
    kzd_devices:set_addresses_emergency(kzd_devices:set_name(kz_json:new(), kz_binary:rand_hex(4))
                                       ,EmergencyAddress
                                       ).
