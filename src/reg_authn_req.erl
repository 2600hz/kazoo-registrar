%%%-----------------------------------------------------------------------------
%%% @copyright (C) 2011-2022, 2600Hz
%%% @doc Handle authn_req messages
%%% @author James Aimonetti
%%% @author Luis Azedo
%%%
%%% This Source Code Form is subject to the terms of the Mozilla Public
%%% License, v. 2.0. If a copy of the MPL was not distributed with this
%%% file, You can obtain one at https://mozilla.org/MPL/2.0/.
%%%
%%% @end
%%%-----------------------------------------------------------------------------
-module(reg_authn_req).

-export([init/0
        ,handle_req/2
        ]).

-include("reg.hrl").

-define(ENCRYPTION_MAP, [{<<"srtp">>, [{<<"RTP-Secure-Media">>, 'true'}]}
                        ,{<<"zrtp">>, [{<<"ZRTP-Secure-Media">>, 'true'}
                                      ,{<<"ZRTP-Enrollment">>, 'true'}
                                      ]}
                        ]).
-define(INTEGRATION_DEVICE_TYPES, [<<"ms_teams">>]).

-spec init() -> 'ok'.
init() -> 'ok'.

-spec handle_req(kapi_authn:req(), kz_term:proplist()) -> 'ok'.
handle_req(AuthnReq, _Props) ->
    'true' = kapi_authn:req_v(AuthnReq),
    _ = kz_log:put_callid(AuthnReq),
    Realm = kapi_authn:get_auth_realm(AuthnReq),
    case kz_network_utils:is_ipv4(Realm)
        orelse kz_network_utils:is_ipv6(Realm)
    of
        'true' ->
            lager:debug("realm is an IP address (~s) : skipping", [Realm]);
        'false' ->
            handle_authn_realm(AuthnReq, Realm)
    end.

handle_authn_realm(AuthnReq, Realm) ->
    Username = kapi_authn:get_auth_user(AuthnReq),
    lager:debug("trying to authenticate ~s@~s", [Username, Realm]),
    case lookup_auth_user(Username, Realm, AuthnReq) of
        {'ok', #auth_user{}=AuthUser} ->
            send_auth_resp(AuthUser, AuthnReq);
        {'error', _R} ->
            lager:notice("auth failure for ~s@~s: ~p", [Username, Realm, _R]),
            send_auth_error(AuthnReq)
    end.

-spec send_auth_resp(auth_user(), kapi_authn:req()) -> 'ok'.
send_auth_resp(#auth_user{password=Password
                         ,username=Username
                         ,method=Method
                         ,realm=Realm
                         ,suppress_unregister_notifications=SupressUnregister
                         ,register_overwrite_notify=RegisterOverwrite
                         ,nonce=Nonce
                         }=AuthUser
              ,AuthnReq
              ) ->
    Category = kz_api:event_category(AuthnReq),
    Resp = props:filter_undefined(
             [{<<"Auth-Method">>, get_auth_method(Method)}
             ,{<<"Auth-Nonce">>, Nonce}
             ,{<<"Auth-Password">>, Password}
             ,{<<"Custom-Channel-Vars">>, create_ccvs(AuthUser)}
             ,{<<"Custom-SIP-Headers">>, create_custom_sip_headers(Method, AuthUser)}
             ,{<<"Expires">>, kz_json:get_integer_value(<<"Expires">>, AuthnReq)}
             ,{<<"Msg-ID">>, kz_api:msg_id(AuthnReq)}
             ,{<<"Register-Overwrite-Notify">>, RegisterOverwrite}
             ,{<<"Suppress-Unregister-Notifications">>, SupressUnregister}
             | kz_api:default_headers(Category, <<"authn_resp">>, ?APP_NAME, ?APP_VERSION)
             ]),
    lager:info("sending SIP authentication reply, with credentials for user ~s@~s",[Username,Realm]),
    kapi_authn:publish_resp(kz_api:server_id(AuthnReq), Resp).

-spec send_auth_error(kapi_authn:req()) -> 'ok'.
send_auth_error(AuthnReq) ->
    %% NOTE: Kamailio needs registrar errors since it is blocking with no
    %%   timeout (at the moment) but when we seek auth for INVITEs we need
    %%   to wait for conferences, etc.  Since Kamailio does not honor
    %%   Defer-Response we can use that flag on registrar errors
    %%   to queue in Kazoo but still advance Kamailio.
    Resp = [{<<"Msg-ID">>, kz_api:msg_id(AuthnReq)}
           ,{<<"Defer-Response">>, <<"true">>}
           | kz_api:default_headers(?APP_NAME, ?APP_VERSION)
           ],
    lager:debug("sending SIP authentication error"),
    kapi_authn:publish_error(kz_api:server_id(AuthnReq), Resp).

-spec create_ccvs(auth_user()) -> kz_json:object().
create_ccvs(#auth_user{doc=JObj
                      ,account_id=AccountId
                      ,account_name=AccountName
                      ,account_normalized_realm=NormalizedRealm
                      ,authorizing_id=AuthorizingId
                      ,authorizing_type=AuthorizingType
                      ,method=Method
                      ,owner_id=OwnerId
                      ,realm=Realm
                      ,register_overwrite_notify=OverwriteNotify
                      ,suppress_unregister_notifications=Suppress
                      ,username=Username
                      }=AuthUser) ->
    kz_json:from_list(
      [{<<"Account-ID">>, AccountId}
      ,{<<"Account-Name">>, AccountName}
      ,{<<"Account-Realm">>, NormalizedRealm}
      ,{<<"Authorizing-ID">>, AuthorizingId}
      ,{<<"Authorizing-Type">>, AuthorizingType}
      ,{<<"Owner-ID">>, OwnerId}
      ,{<<"Presence-ID">>, maybe_get_presence_id(AuthUser)}
      ,{<<"Pusher-Application">>, kz_json:get_value([<<"push">>, <<"Token-App">>], JObj)}
      ,{<<"Realm">>, Realm}
      ,{<<"Register-Overwrite-Notify">>, OverwriteNotify}
      ,{<<"Suppress-Unregister-Notifications">>, Suppress}
      ,{<<"Username">>, Username}
      | (create_specific_ccvs(AuthUser, Method)
         ++ generate_security_ccvs(AuthUser)
         ++ maybe_add_hotdesk_current_id(AuthUser)
        )
      ]).

-spec maybe_get_presence_id(auth_user()) -> kz_term:api_binary().
maybe_get_presence_id(#auth_user{account_db=AccountDb
                                ,authorizing_id=DeviceId
                                ,account_realm=AccountRealm
                                }
                     ) ->
    case get_presence_id(AccountDb, DeviceId) of
        'undefined' -> 'undefined';
        PresenceId ->
            case binary:match(PresenceId, <<"@">>) of
                'nomatch' -> <<PresenceId/binary, "@", AccountRealm/binary>>;
                _ -> PresenceId
            end
    end.

-spec get_presence_id(kz_term:api_ne_binary(), kz_term:api_ne_binary()) -> kz_term:api_ne_binary().
get_presence_id('undefined', _) -> 'undefined';
get_presence_id(_, 'undefined') -> 'undefined';
get_presence_id(AccountDb, DeviceId) ->
    get_device_presence_id(AccountDb, DeviceId).

-spec get_device_presence_id(kz_term:ne_binary(), kz_term:ne_binary()) -> kz_term:api_ne_binary().
get_device_presence_id(AccountDb, DeviceId) ->
    case kz_datamgr:open_cache_doc(AccountDb, DeviceId) of
        {'error', _} -> 'undefined';
        {'ok', DeviceJObj} ->
            case kzd_devices:calculate_presence_id(DeviceJObj) of
                'undefined' -> 'undefined';
                PresenceId -> PresenceId
            end
    end.

-spec create_specific_ccvs(auth_user(), kz_term:ne_binary()) -> kz_term:proplist().
create_specific_ccvs(#auth_user{msisdn=MSISDN}, ?GSM_ANY_METHOD) ->
    [{<<"Caller-ID">>, MSISDN}
    ,{<<"Caller-ID-Number">>, MSISDN}
    ];
create_specific_ccvs(_, _) -> [].

-spec create_custom_sip_headers(kz_term:api_binary(), auth_user()) -> kz_term:api_object().
create_custom_sip_headers(?GSM_ANY_METHOD
                         ,#auth_user{a3a8_kc=KC
                                    ,a3a8_sres=SRES
                                    ,msisdn=Number
                                    ,account_realm=AccountRealm
                                    ,realm=Realm
                                    ,username=Username
                                    }
                         ) ->
    create_custom_sip_headers(
      props:filter_undefined(
        [{<<"P-Asserted-Identity">>, <<"<sip:", Username/binary, "@", Realm/binary, ">">>}
        ,{<<"P-Associated-URI">>, <<"<sip:", Username/binary, "@", AccountRealm/binary, ">">>}
        ,{<<"P-Associated-URI">>, get_tel_uri(Number)}
        ,{<<"P-GSM-Kc">>, KC}
        ,{<<"P-GSM-SRes">>, SRES}
        ,{<<"P-Kazoo-Primary-Number">>, Number}
        ])
     );
create_custom_sip_headers(?ANY_AUTH_METHOD, _) -> 'undefined'.

-spec create_custom_sip_headers(kz_term:proplist()) -> kz_term:api_object().
create_custom_sip_headers([]) -> 'undefined';
create_custom_sip_headers(Props) -> kz_json:from_list(Props).

-spec get_tel_uri(kz_term:api_binary()) -> kz_term:api_binary().
get_tel_uri('undefined') -> 'undefined';
get_tel_uri(Number) -> <<"<tel:", Number/binary,">">>.

%%------------------------------------------------------------------------------
%% @doc look up the user and realm in the database and return the result
%% @end
%%------------------------------------------------------------------------------
-spec lookup_auth_user(kz_term:ne_binary(), kz_term:ne_binary(), kapi_authn:req()) -> auth_response().
lookup_auth_user(Username, Realm, AuthnReq) ->
    case get_auth_user(Username, Realm) of
        {'error', _}=E -> E;
        {'ok', ViewResult} ->
            AuthUser = check_auth_user(ViewResult, Username, Realm, AuthnReq),
            maybe_perform_integration_device_checks(AuthUser, ViewResult, AuthnReq)
    end.

-spec get_auth_user(kz_term:ne_binary(), kz_term:ne_binary()) ->
          {'ok', kz_json:object()} |
          {'error', 'not_found'}.
get_auth_user(Username, Realm) ->
    case kapps_util:get_account_by_realm(Realm) of
        {'error', E} ->
            lager:debug("failed to lookup realm ~s in accounts: ~p", [Realm, E]),
            get_auth_user_in_agg(Username, Realm);
        {'multiples', []} ->
            lager:debug("failed to find realm ~s in accounts", [Realm]),
            get_auth_user_in_agg(Username, Realm);
        {'multiples', [AccountDB|_]} ->
            lager:debug("found multiple accounts by realm ~s, using first: ~s", [Realm, AccountDB]),
            get_auth_user_in_account(Username, Realm, AccountDB);
        {'ok', AccountDB} ->
            get_auth_user_in_account(Username, Realm, AccountDB)
    end.

-spec get_auth_user_in_agg(kz_term:ne_binary(), kz_term:ne_binary()) ->
          {'ok', kz_json:object()} |
          {'error', 'not_found'}.
get_auth_user_in_agg(Username, Realm) ->
    get_auth_user_in_agg(Username, Realm, kapps_config:get_is_true(?CONFIG_CAT, <<"use_aggregate">>, 'true')).

get_auth_user_in_agg(_Username, _Realm, 'false') ->
    lager:debug("SIP credential aggregate db is disabled"),
    {'error', 'not_found'};
get_auth_user_in_agg(Username, Realm, 'true') ->
    ViewOptions = [{'key', [Realm, Username]}
                  ,'include_docs'
                  ],
    case kz_datamgr:get_results(?KZ_SIP_DB, <<"credentials/lookup">>, ViewOptions) of
        {'error', _R} ->
            lager:warning("failed to look up SIP credentials ~p in aggregate", [_R]),
            {'error', 'not_found'};
        {'ok', []} ->
            lager:debug("~s@~s not found in aggregate", [Username, Realm]),
            {'error', 'not_found'};
        {'ok', [ViewResult|_]} ->
            lager:debug("~s@~s found in aggregate", [Username, Realm]),
            {'ok', ViewResult}
    end.

-spec get_auth_user_in_account(kz_term:ne_binary(), kz_term:ne_binary(), kz_term:ne_binary()) ->
          {'ok', kz_json:object()} |
          {'error', 'not_found'}.
get_auth_user_in_account(Username, Realm, AccountDB) ->
    ViewOptions = [{'key', Username}
                  ,'include_docs'
                  ],
    case kz_datamgr:get_results(AccountDB, <<"devices/sip_credentials">>, ViewOptions) of
        {'error', _R} ->
            lager:warning("failed to look up SIP credentials in ~s: ~p", [AccountDB, _R]),
            get_auth_user_in_agg(Username, Realm);
        {'ok', []} ->
            lager:debug("~s@~s not found in ~s", [Username, Realm, AccountDB]),
            get_auth_user_in_agg(Username, Realm);
        {'ok', [ViewResult|_]} ->
            lager:debug("~s@~s found in account db: ~s", [Username, Realm, AccountDB]),
            {'ok', ViewResult}
    end.

%%------------------------------------------------------------------------------
%% @doc
%% @end
%%------------------------------------------------------------------------------
-spec check_auth_user(kz_json:object(), kz_term:ne_binary(), kz_term:ne_binary(), kapi_authn:req()) -> auth_response().
check_auth_user(ViewResult, Username, Realm, AuthnReq) ->
    Things = [{<<"account">>, get_account_id(ViewResult)}
             ,{kz_json:get_value([<<"doc">>, <<"pvt_type">>], ViewResult), kz_doc:id(ViewResult)}
             ,{<<"owner">>, kz_json:get_value([<<"doc">>, <<"owner_id">>], ViewResult)}
             ],
    case kapps_util:are_all_enabled(Things) of
        'true' ->
            jobj_to_auth_user(ViewResult, Username, Realm, AuthnReq);
        {'false', Reason} ->
            lager:notice("rejecting authn because ~p", [Reason]),
            {'error', 'disabled'}
    end.

-spec jobj_to_auth_user(kz_json:object(), kz_term:ne_binary(), kz_term:ne_binary(), kapi_authn:req()) -> auth_response().
jobj_to_auth_user(ViewResult, Username, Realm, AuthnReq) ->
    SIPSettings = get_auth_value(ViewResult),
    AuthDoc = kz_json:get_json_value(<<"doc">>, ViewResult),
    Method = get_auth_method(AuthDoc),
    AuthUser = #auth_user{account_db = get_account_db(AuthDoc)
                         ,account_id = get_account_id(AuthDoc)
                         ,authorizing_id = kz_doc:id(ViewResult)
                         ,authorizing_type = get_auth_type(AuthDoc)
                         ,doc=AuthDoc
                         ,method = kz_term:to_lower_binary(Method)
                         ,owner_id = kzd_devices:owner_id(AuthDoc)
                         ,password = kz_json:get_ne_binary_value(<<"password">>, SIPSettings, kz_binary:rand_hex(6))
                         ,realm = Realm
                         ,register_overwrite_notify = kzd_devices:register_overwrite_notify(AuthDoc)
                         ,request=AuthnReq
                         ,suppress_unregister_notifications = kzd_devices:suppress_unregister_notifications(AuthDoc)
                         ,username = Username
                         },
    maybe_auth_method(add_account_name(AuthUser), AuthDoc, AuthnReq, Method).

-spec get_auth_type(kz_json:object()) -> kz_term:ne_binary().
get_auth_type(AuthDoc) ->
    case kz_json:get_first_defined([<<"endpoint_type">>, <<"device_type">>], AuthDoc) of
        <<"mobile">> -> <<"mobile">>;
        _ -> kz_doc:type(AuthDoc, <<"anonymous">>)
    end.

-spec get_auth_value(kz_json:object()) -> kz_term:api_object().
get_auth_value(JObj) ->
    kz_json:get_first_defined([[<<"doc">>,<<"sip">>]
                              ,<<"value">>
                              ]
                             ,JObj
                             ).

-spec add_account_name(auth_user()) -> auth_user().
add_account_name(#auth_user{account_id=AccountId}=AuthUser) ->
    case kzd_accounts:fetch(AccountId) of
        {'error', _} -> AuthUser;
        {'ok', Account} ->
            Realm = kzd_accounts:realm(Account),
            AuthUser#auth_user{account_name = kzd_accounts:name(Account)
                              ,account_realm = Realm
                              ,account_normalized_realm = kz_term:to_lower_binary(Realm)
                              }
    end.

-spec get_auth_method(kz_json:object() | kz_term:ne_binary()) -> kz_term:ne_binary().
get_auth_method(?GSM_ANY_METHOD=M) when is_binary(M)-> <<"gsm">>;
get_auth_method(M) when is_binary(M) -> M;
get_auth_method(JObj) ->
    kz_json:get_first_defined([[<<"gsm">>,<<"method">>]
                              ,[<<"sip">>,<<"method">>]
                              ]
                             ,JObj
                             ,<<"password">>
                             ).

-spec maybe_auth_method(auth_user(), kz_json:object(), kapi_authn:req(), kz_term:ne_binary()) -> auth_response().
maybe_auth_method(AuthUser, JObj, AuthnReq, ?GSM_ANY_METHOD)->
    GsmDoc = kz_json:get_value(<<"gsm">>, JObj),
    CachedNonce = kz_json:get_value(<<"nonce">>, GsmDoc, kz_binary:rand_hex(16)),
    Nonce = remove_dashes(
              kz_json:get_first_defined([<<"nonce">>, <<"Auth-Nonce">>], AuthnReq, CachedNonce)
             ),
    GsmKey = kz_json:get_value(<<"key">>, GsmDoc),
    GsmSRes = kz_json:get_value(<<"sres">>, GsmDoc, kz_binary:rand_hex(6)),
    GsmNumber = kz_json:get_value(<<"msisdn">>, GsmDoc),
    ReqMethod = kz_json:get_value(<<"Method">>, AuthnReq),
    gsm_auth(
      maybe_update_gsm(ReqMethod
                      ,AuthUser#auth_user{msisdn=GsmNumber
                                         ,a3a8_key=GsmKey
                                         ,a3a8_sres=GsmSRes
                                         ,nonce=Nonce
                                         }
                      )
     );
maybe_auth_method(AuthUser, _JObj, _Req, ?ANY_AUTH_METHOD)->
    {'ok', AuthUser}.

%%------------------------------------------------------------------------------
%% @doc If device_type=softphone or any integration services device type, some
%% checks are performed. If softphone, Kazoo needs to check the register request
%% is not from an integration service (integration_as_softphone). If not softphone
%% but an actual integration service; request's User Agent needs to be whitelisted
%% via User Agent regexes list (request_user_agent) and also the request's source
%% IP needs to be whitelisted as well and not denied (request_source_ip).
%% @end
%%------------------------------------------------------------------------------
-spec maybe_perform_integration_device_checks(auth_response(), kz_json:object(), kapi_authn:req()) -> auth_response().
maybe_perform_integration_device_checks({'ok', _AuthUser} = Ret, ViewResult, AuthnReq) ->
    DeviceType = kzd_devices:device_type(kz_json:get_json_value(<<"doc">>, ViewResult)),
    case lists:member(DeviceType, [<<"softphone">> | ?INTEGRATION_DEVICE_TYPES]) of
        'false' ->
            lager:debug("not a softphone device nor an integration service device, not need to run checks"),
            Ret;
        'true' ->
            perform_integration_device_checks(Ret, AuthnReq, DeviceType)
    end;
maybe_perform_integration_device_checks({'error', _Reason} = AuthFailed, _ViewResult, _AuthnReq) ->
    AuthFailed.

perform_integration_device_checks(Ret, AuthnReq, DeviceType) ->
    lager:debug("~s device trying to register, running checks", [DeviceType]),
    SourceIP = kz_json:get_ne_binary_value(<<"Orig-IP">>, AuthnReq),
    UserAgent = kz_json:get_ne_binary_value(<<"User-Agent">>, AuthnReq),
    UARegexes = kapps_config:get_ne_binaries(?CONFIG_CAT, <<"integrations_user_agent_regexes">>, []),
    {'ok', MP} = re:compile(kz_binary:join(UARegexes, <<"|">>)), %% <<"regex1|regex2|regexn">> before regex compilation
    %% If any of the checks fail, the remaining ones are not executed.
    Checks = [fun check_integration_as_softphone/5 %% if integration_as_softphone, forbid registration.
             ,fun check_request_user_agent/5 %% if not softphone, check user agent (integration service) is whitelisted.
             ,fun check_request_source_ip/5 %% check request's source IP is allowed and not denied to register.
             ],
    lists:foldl(fun(F, Acc) -> F(Acc, DeviceType, SourceIP, UserAgent, MP) end
               ,maybe_undefined_user_agent(Ret, UserAgent)
               ,Checks
               ).

-spec maybe_undefined_user_agent(auth_response(), kz_term:api_ne_binary()) -> auth_response().
maybe_undefined_user_agent(_AuthResponse, 'undefined') ->
    lager:debug("not user agent provided within the register request, denying registration"),
    {'error', 'invalid_user_agent'};
maybe_undefined_user_agent(AuthResponse, _UserAgent) ->
    AuthResponse.

%%------------------------------------------------------------------------------
%% @doc Checks if an "integration" (MS Teams, residential) device is trying to register
%% as a softphone device (which is forbidden).
%%
%% If device_type = `softphone' and request's User-Agent matches any of the integration services'
%% user-agent regexes, forbid registration.
%% @end
%%------------------------------------------------------------------------------
-spec check_integration_as_softphone(auth_response(), kz_term:ne_binary(), kz_term:ne_binary(), kz_term:ne_binary(), binary()) -> auth_response().
check_integration_as_softphone({'ok', _AuthUser} = Ret, <<"softphone">>, _SourceIP, UserAgent, CompiledRegex) ->
    lager:debug("checking if user agent (~s) is not from an integration service", [UserAgent]),
    case re:run(UserAgent, CompiledRegex, ['notempty']) of
        {'match', _} ->
            lager:debug("trying to register '~s' integration device as a softphone, forbidden", [UserAgent]),
            {'error', 'integration_as_softphone'};
        'nomatch' ->
            lager:debug("'~s' seems to be a regular softphone client, continue", [UserAgent]),
            Ret
    end;
check_integration_as_softphone({'ok', _AuthUser} = Ret, _IntegrationDevice, _SourceIP, _UserAgent, _CompiledRegex) ->
    lager:debug("integration device '~s' not using a softphone to register, continue", [_IntegrationDevice]),
    Ret;
check_integration_as_softphone({'error', _Reason} = AuthFailed, _DeviceType, _SourceIP, _UserAgent, _CompiledRegex) ->
    AuthFailed.

%%------------------------------------------------------------------------------
%% @doc If device_type=softphone and it is not an intent to use a softphone device
%% register an integration service device, let it continue without checking UA.
%%
%% If not a softphone, it is an integration service device, check its UA matches
%% any of the user agent regexes within the configuration.
%% @end
%%------------------------------------------------------------------------------
-spec check_request_user_agent(auth_response(), kz_term:ne_binary(), kz_term:ne_binary(), kz_term:ne_binary(), binary()) -> auth_response().
check_request_user_agent(Ret, <<"softphone">>, _SourceIP, _UserAgent, _CompiledRegex) ->
    %% Only check User Agent for integration services devices.
    Ret;
check_request_user_agent({'ok', _AuthUser} = Ret, _DeviceType, _SourceIP, UserAgent, CompiledRegex) ->
    lager:debug("checking request's user agent (integration service) is allowed to register"),
    case re:run(UserAgent, CompiledRegex, ['notempty']) of
        'nomatch' ->
            lager:debug("'~s' is not whitelisted, denying registration", [UserAgent]),
            {'error', 'not_allowed'};
        {'match', _} ->
            lager:debug("'~s' user agent is whitelisted, continue", [UserAgent]),
            Ret
    end;
check_request_user_agent({'error', _Reason} = AuthFailed, _DeviceType, _SourceIP, _UserAgent, _CompiledRegex) ->
    AuthFailed.

%%------------------------------------------------------------------------------
%% @doc If user_auth was successful, device_type is "ms_teams" and source_ip is
%% allowed and not on the denied list, allow the registration, deny the
%% registration otherwise.
%% @end
%%------------------------------------------------------------------------------
-spec check_request_source_ip(auth_response(), kz_term:ne_binary(), kz_term:ne_binary(), kz_term:ne_binary(), binary()) -> auth_response().
check_request_source_ip({'ok', _AuthUser} = Ret, DeviceType, SourceIP, _UserAgent, _CompiledRegex) ->
    lager:debug("checking request's source IP: ~s", [SourceIP]),
    ACL = access_control(DeviceType),
    case lists:member(SourceIP, kz_json:get_ne_binaries(<<"deny">>, ACL, []))
        orelse not lists:member(SourceIP, kz_json:get_ne_binaries(<<"allow">>, ACL, []))
    of
        'true' ->
            lager:debug("~s denied or not allowed, denying registration", [SourceIP]),
            {'error', 'not_allowed'};
        'false' ->
            lager:debug("~s allowed, continue", [SourceIP]),
            Ret
    end;
check_request_source_ip({'error', _Reason} = AuthFailed, _DeviceType, _SourceIP, _UserAgent, _CompiledRegex) ->
    AuthFailed.

-spec access_control(kz_term:ne_binary()) -> kz_json:object().
access_control(AuthOrDeviceType) ->
    Default = kapps_config:get_json(?CONFIG_CAT
                                   ,[<<"access_control">>, <<"default">>]
                                   ,kz_json:from_list([{<<"allow">>, []}, {<<"deny">>, []}])
                                   ),
    kapps_config:get_json(?CONFIG_CAT, [<<"access_control">>, AuthOrDeviceType], Default).


-define(GSM_PRE_REGISTER_ROUTINES, [fun maybe_msisdn/1]).
-define(GSM_REGISTER_ROUTINES, [fun maybe_msisdn/1]).

-spec maybe_update_gsm(kz_term:api_binary(), auth_user()) -> auth_user().
maybe_update_gsm(<<"PRE-REGISTER">>, AuthUser) ->
    lists:foldl(fun(F,A) -> F(A) end, AuthUser, ?GSM_PRE_REGISTER_ROUTINES);
maybe_update_gsm(<<"REGISTER">>, AuthUser) ->
    lists:foldl(fun(F,A) -> F(A) end, AuthUser, ?GSM_REGISTER_ROUTINES);
maybe_update_gsm(_, AuthUser) -> AuthUser.

-spec maybe_msisdn(auth_user()) -> auth_user().
maybe_msisdn(#auth_user{msisdn='undefined'
                       ,owner_id='undefined'
                       ,authorizing_id=Id
                       }=AuthUser) ->
    maybe_msisdn_from_callflows(AuthUser, <<"device">>, Id);
maybe_msisdn(#auth_user{msisdn='undefined'
                       ,owner_id=OwnerId
                       }=AuthUser) ->
    maybe_msisdn_from_callflows(AuthUser, <<"user">>, OwnerId);
maybe_msisdn(AuthUser) -> AuthUser.

-spec maybe_msisdn_from_callflows(auth_user(), kz_term:ne_binary(), kz_term:ne_binary()) -> auth_user().
maybe_msisdn_from_callflows(#auth_user{account_db=AccountDB}=AuthUser
                           ,Type
                           ,Id
                           ) ->
    ViewOptions = [{'startkey', [Type, Id]}
                  ,{'endkey', [Type, Id, <<"9999999">>]}
                  ],
    case kz_datamgr:get_results(AccountDB, <<"callflows/msisdn">>, ViewOptions) of
        {'error', _R} ->
            lager:warning("failed to look up msisdn  in ~s: ~p", [AccountDB, _R]),
            AuthUser;
        {'ok', []} ->
            lager:debug("msisdn not found for ~s@~s in ~s", [Type, Id, AccountDB]),
            AuthUser;
        {'ok', [User|_]} ->
            MSISDN = kz_json:get_value([<<"value">>,<<"msisdn">>], User),
            lager:debug("found msisdn ~s for ~s@~s in account db: ~s"
                       ,[MSISDN, Type, Id, AccountDB]
                       ),
            AuthUser#auth_user{msisdn=MSISDN}
    end.

-spec gsm_auth(auth_user()) -> {'ok', auth_user()}.
gsm_auth(#auth_user{method=?GSM_CACHED_METHOD
                   ,a3a8_sres=SRES
                   }=AuthUser) ->
    {'ok', AuthUser#auth_user{password=SRES}};
gsm_auth(#auth_user{method=?GSM_A3A8_METHOD
                   ,a3a8_key=GsmKey
                   ,nonce=NonceHex
                   }=AuthUser) ->
    Key = kz_binary:from_hex(GsmKey),
    Nonce = kz_binary:from_hex(NonceHex),
    SRes = registrar_crypto:a3a8(Nonce, Key),
    SResHex = kz_term:to_hex_binary(SRes),
    <<SRES:8/binary, KC/binary>> = SResHex,
    {'ok', AuthUser#auth_user{a3a8_sres=SRES
                             ,a3a8_kc=KC
                             ,password=SRES
                             }};
gsm_auth(AuthUser) -> {'ok', AuthUser}.

%%------------------------------------------------------------------------------
%% @doc
%% @end
%%------------------------------------------------------------------------------
-spec get_account_id(kz_json:object()) -> kz_term:api_binary().
get_account_id(JObj) ->
    case get_account_db(JObj) of
        'undefined' -> 'undefined';
        AccountDb -> kzs_util:format_account_id(AccountDb)
    end.

%%------------------------------------------------------------------------------
%% @doc
%% @end
%%------------------------------------------------------------------------------
-spec get_account_db(kz_json:object()) -> kz_term:api_binary().
get_account_db(JObj) ->
    case kz_json:get_first_defined([[<<"doc">>, <<"pvt_account_db">>]
                                   ,<<"pvt_account_db">>
                                   ,[<<"doc">>, <<"pvt_account_id">>]
                                   ,<<"pvt_account_id">>
                                   ], JObj)
    of
        'undefined' -> 'undefined';
        AccountDb -> kzs_util:format_account_db(AccountDb)
    end.

-spec remove_dashes(kz_term:ne_binary()) -> kz_term:ne_binary().
remove_dashes(Bin) ->
    << <<B>> || <<B>> <= Bin, B =/= $->>.

-spec encryption_method_map(kz_term:proplist(), kz_term:api_binaries() | kz_json:object()) -> kz_term:proplist().
encryption_method_map(Props, []) -> Props;
encryption_method_map(Props, [Method|Methods]) ->
    case props:get_value(Method, ?ENCRYPTION_MAP, []) of
        [] -> encryption_method_map(Props, Methods);
        Values -> encryption_method_map(props:set_values(Values, Props), Methods)
    end;
encryption_method_map(Props, JObj) ->
    Key = [<<"media">>, <<"encryption">>, <<"methods">>],
    Methods = kz_json:get_value(Key, JObj, []),
    encryption_method_map(Props, Methods).


-spec generate_security_ccvs(auth_user()) -> kz_term:proplist().
generate_security_ccvs(#auth_user{}=User) ->
    generate_security_ccvs(User, []).

-spec generate_security_ccvs(auth_user(), kz_term:proplist()) -> kz_term:proplist().
generate_security_ccvs(#auth_user{}=User, Acc0) ->
    CCVFuns = [fun maybe_enforce_security/1
              ,fun maybe_set_encryption_flags/1
              ],
    {_, Acc} = lists:foldl(fun(F, Acc) -> F(Acc) end, {User, Acc0}, CCVFuns),
    Acc.

-spec maybe_enforce_security({auth_user(), kz_term:proplist()}) -> {auth_user(), kz_term:proplist()}.
maybe_enforce_security({#auth_user{doc=JObj}=User, Acc}) ->
    case kz_json:is_true([<<"media">>
                         ,<<"encryption">>
                         ,<<"enforce_security">>
                         ]
                        ,JObj
                        ,'false'
                        )
    of
        'true' -> {User, [{<<"Media-Encryption-Enforce-Security">>, 'true'} | Acc]};
        'false' -> {User, Acc}
    end.

-spec maybe_set_encryption_flags({auth_user(), kz_term:proplist()}) -> {auth_user(), kz_term:proplist()}.
maybe_set_encryption_flags({#auth_user{doc=JObj}=User, Acc}) ->
    {User, encryption_method_map(Acc, JObj)}.

-spec maybe_add_hotdesk_current_id(auth_user()) -> kz_term:proplist().
maybe_add_hotdesk_current_id(#auth_user{doc=JObj}) ->
    case kzd_devices:hotdesk_ids(JObj, []) of
        [] -> [];
        [Id | _] -> [{<<"Hotdesk-Current-ID">>, Id}]
    end.
