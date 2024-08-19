%%%-----------------------------------------------------------------------------
%%% @copyright (C) 2011-2024, 2600Hz
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

-export([handle_req/2
        ,get_auth_user/2
        ]).

-ifdef(TEST).
-export([maybe_check_emergency_address/3]).
-endif.

-include("reg.hrl").

-define(ENCRYPTION_MAP, [{<<"srtp">>, [{<<"RTP-Secure-Media">>, 'true'}]}
                        ,{<<"zrtp">>, [{<<"ZRTP-Secure-Media">>, 'true'}
                                      ,{<<"ZRTP-Enrollment">>, 'true'}
                                      ]}
                        ]).
-define(INTEGRATION_DEVICE_TYPES
       ,kapps_config:get_ne_binaries(?CONFIG_CAT, <<"integration_device_types">>, [<<"teammate">>])
       ).
-define(CHECK_DEVICE_EMERGENCY_ADDRESS
       ,kapps_config:get_boolean(?CONFIG_CAT, <<"should_check_device_emergency_address">>, 'false')
       ).

-spec handle_req(kapi_authn:req(), kz_term:proplist()) -> 'ok'.
handle_req(AuthnReq, _Props) ->
    'true' = kapi_authn:req_v(AuthnReq),
    _ = kz_log:put_callid(AuthnReq),
    handle_req_method(AuthnReq, kapi_authn:get_auth_user(AuthnReq), kapi_authn:get_auth_realm(AuthnReq), authn_method(AuthnReq)).

authn_method(AuthnReq) ->
    kz_json:get_ne_binary_value(<<"Method">>, AuthnReq, <<"REGISTER">>).

handle_req_method(AuthnReq, MDN, Realm, <<"MDN">>) ->
    handle_authn_mdn(AuthnReq, MDN, Realm);
handle_req_method(AuthnReq, Username, Realm, _Method) ->
    case kz_network_utils:is_ip(Realm) of
        'true' ->
            lager:debug("realm is an IP address (~s) : skipping", [Realm]);
        'false' ->
            handle_authn_register(AuthnReq, Username, Realm)
    end.

handle_authn_mdn(AuthnReq, MDN, Realm) ->
    case knm_phone_number:fetch(MDN) of
        {'ok', Number} ->
            verify_mdn(AuthnReq, Number, MDN, Realm);
        {'error', 'not_found'} ->
            lager:info("mdn ~s not found", [MDN]),
            send_auth_error(AuthnReq);
        {'error', _Error} ->
            lager:error("error while trying to fetch mdn ~s => ~p", [MDN, _Error]),
            send_auth_error(AuthnReq)
    end.

mdn_device_id(Number) ->
    kz_json:get_ne_binary_value([<<"mobile">>, <<"device-id">>], knm_phone_number:doc(Number)).

mdn_account_id(Number) ->
    knm_phone_number:assigned_to(Number).

mdn_is_active(Number) ->
    knm_phone_number:state(Number) =:= <<"in_service">>.

verify_mdn(AuthnReq, Number, MDN, Realm) ->
    case mdn_is_active(Number)
        andalso mdn_account_id(Number)
    of
        'false' ->
            lager:info("mdn ~s is not active", [MDN]),
            send_auth_error(AuthnReq);
        'undefined' ->
            lager:info("mdn ~s is not assigned", [MDN]),
            send_auth_error(AuthnReq);
        AccountId ->
            verify_mdn_device(AuthnReq, Number, MDN, Realm, AccountId)
    end.

verify_mdn_device(AuthnReq, Number, MDN, Realm, AccountId) ->
    case mdn_device_id(Number) of
        'undefined' ->
            lager:info("mdn ~s is not assigned to a device on account ~s", [MDN, AccountId]),
            send_auth_error(AuthnReq);
        DeviceId ->
            verify_mdn_endpoint(AuthnReq, MDN, Realm, AccountId, DeviceId)
    end.

verify_mdn_endpoint(AuthnReq, MDN, Realm, AccountId, DeviceId) ->
    case kz_datamgr:open_doc(AccountId, DeviceId) of
        {'ok', EndpointDoc} ->
            check_mdn_endpoint(AuthnReq, MDN, check_auth_user(EndpointDoc, MDN, Realm, AuthnReq));
        {'error', 'not_found'} ->
            lager:error("device ~s on account ~s not found for mdn ~s", [DeviceId, AccountId, MDN]),
            send_auth_error(AuthnReq);
        {'error', _Error} ->
            lager:error("error reading mdn ~s device ~s/~s => ~p", [MDN, DeviceId, AccountId, _Error]),
            send_auth_error(AuthnReq)
    end.

check_mdn_endpoint(AuthnReq, _MDN, {'ok', #auth_user{}=AuthUser}) ->
    lager:debug("sending mdn-trusted reply for mdn ~s", [_MDN]),
    send_auth_resp(AuthUser#auth_user{method = <<"mdn-trusted">>, password = kz_binary:rand_hex(5)}, AuthnReq);
check_mdn_endpoint(AuthnReq, _MDN, _Err) ->
    lager:info("error verifying mdn ~s => ~p", [_MDN, _Err]),
    send_auth_error(AuthnReq).

handle_authn_register(AuthnReq, Username, Realm) ->
    lager:debug("trying to authenticate ~s@~s", [Username, Realm]),
    case lookup_auth_user(AuthnReq, Username, Realm) of
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
      ,{<<"Presence-Monitoring-Aliases">>, presence_aliases(AuthUser)}
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

-spec presence_aliases(auth_user() | kz_json:object()) -> kz_term:api_ne_binaries().
presence_aliases(#auth_user{account_id = AccountId, authorizing_id = EndpointId}) ->
    case kz_endpoint:get(EndpointId, AccountId) of
        {'ok', Endpoint} -> presence_aliases(Endpoint);
        _Other -> 'undefined'
    end;
presence_aliases(Endpoint) ->
    case lists:filtermap(fun presence_id/1, presence_ids(Endpoint)) of
        [] -> 'undefined';
        Filtered -> Filtered
    end.

-spec presence_ids(kz_json:object()) -> kz_term:ne_binaries().
presence_ids(Endpoint) ->
    [kzd_endpoint:presence_id(Endpoint)
    | kzd_endpoint:presence_monitoring_aliases(Endpoint, [])
    ].

presence_id('undefined') -> 'false';
presence_id(PresenceId) ->
    [User | _ ] = binary:split(PresenceId, <<"@">>),
    {'true', User}.

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
        {'ok', DeviceJObj} -> kzd_devices:calculate_presence_id(DeviceJObj)
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
-spec lookup_auth_user(kapi_authn:req(), kz_term:ne_binary(), kz_term:ne_binary()) -> auth_response().
lookup_auth_user(AuthnReq, Username, Realm) ->
    case get_auth_user(Username, Realm) of
        {'error', _}=E -> E;
        {'ok', AuthDoc} -> run_checks(AuthnReq, Username, Realm, AuthDoc)
    end.

run_checks(AuthnReq, Username, Realm, AuthDoc) ->
    case check_auth_user(AuthnReq, Username, Realm, AuthDoc) of
        {'error', _} = AuthFailed -> AuthFailed;
        {'ok', #auth_user{}} = AuthResp -> run_checks(AuthResp, AuthnReq, authn_method(AuthnReq))
    end.

-spec run_checks(auth_response(), kapi_authn:req(), kz_term:ne_binary()) -> auth_response().
run_checks(AuthResp, AuthnReq, <<"REGISTER">>) ->
    %% Checks to be run for REGISTER requests.
    run_checks(AuthResp, AuthnReq);
run_checks(AuthResp, AuthnReq, <<"INVITE">>) ->
    %% Checks to be run for INVITE requests.
    run_checks(AuthResp, AuthnReq);
run_checks(AuthResp, _AuthnReq, _) ->
    AuthResp.

-spec run_checks(auth_response(), kapi_authn:req()) -> auth_response().
run_checks(AuthResp, AuthnReq) ->
    Checks = [fun maybe_check_emergency_address/2
             ,fun maybe_perform_integration_device_checks/2
             ],
    lists:foldl(fun(Check, Acc) -> Check(Acc, AuthnReq) end, AuthResp, Checks).

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
        {'multiples', [AccountDb|_]} ->
            lager:debug("found multiple accounts by realm ~s, using first: ~s", [Realm, AccountDb]),
            get_auth_user_in_account(Username, Realm, AccountDb);
        {'ok', AccountDb} ->
            get_auth_user_in_account(Username, Realm, AccountDb)
    end.

-spec use_aggregate() -> boolean().
use_aggregate() ->
    kapps_config:get_is_true(?CONFIG_CAT, <<"use_aggregate">>, 'true').

-spec get_auth_user_in_agg(kz_term:ne_binary(), kz_term:ne_binary()) ->
          {'ok', kz_json:object()} |
          {'error', 'not_found'}.
get_auth_user_in_agg(Username, Realm) ->
    get_auth_user_in_agg(Username, Realm, use_aggregate()).

get_auth_user_in_agg(_Username, _Realm, 'false') ->
    lager:debug("SIP credential aggregate db is disabled"),
    {'error', 'not_found'};
get_auth_user_in_agg(Username, Realm, 'true') ->
    case kz_datamgr:get_result_doc(?KZ_SIP_DB, <<"credentials/lookup">>, [Realm, Username]) of
        {'error', _R} ->
            lager:warning("failed to look up SIP credentials ~p in aggregate", [_R]),
            {'error', 'not_found'};
        {'ok', Doc} ->
            lager:debug("~s@~s found in aggregate", [Username, Realm]),
            {'ok', Doc}
    end.

-spec get_auth_user_in_account(kz_term:ne_binary(), kz_term:ne_binary(), kz_term:ne_binary()) ->
          {'ok', kz_json:object()} |
          {'error', 'not_found'}.
get_auth_user_in_account(Username, Realm, AccountDb) ->
    case kz_datamgr:get_result_doc(AccountDb, <<"devices/sip_credentials">>, Username) of
        {'error', _R} ->
            lager:warning("failed to look up SIP credentials in ~s: ~p", [AccountDb, _R]),
            get_auth_user_in_agg(Username, Realm);
        {'ok', Doc} ->
            lager:debug("~s@~s found in account db: ~s", [Username, Realm, AccountDb]),
            {'ok', Doc}
    end.

%%------------------------------------------------------------------------------
%% @doc
%% @end
%%------------------------------------------------------------------------------
-spec check_auth_user(kapi_authn:req(), kz_term:ne_binary(), kz_term:ne_binary(), kz_json:object()) -> auth_response().
check_auth_user(AuthnReq, Username, Realm, AuthDoc) ->
    Things = [{<<"account">>, kz_doc:account_id(AuthDoc)}
             ,{kz_doc:type(AuthDoc), kz_doc:id(AuthDoc)}
             ,{<<"owner">>, kzd_devices:owner_id(AuthDoc)}
             ],
    case kapps_util:are_all_enabled(Things) of
        'true' ->
            auth_user(AuthnReq, Username, Realm, AuthDoc);
        {'false', Reason} ->
            lager:notice("rejecting authn because ~p", [Reason]),
            {'error', 'disabled'}
    end.

-spec auth_user(kapi_authn:req(), kz_term:ne_binary(), kz_term:ne_binary(), kz_json:object()) -> auth_response().
auth_user(AuthnReq, Username, Realm, AuthDoc) ->
    Method = get_auth_method(AuthDoc),
    AuthUser = #auth_user{account_db = get_account_db(AuthDoc)
                         ,account_id = get_account_id(AuthDoc)
                         ,authorizing_id = kz_doc:id(AuthDoc)
                         ,authorizing_type = get_auth_type(AuthDoc)
                         ,doc=AuthDoc
                         ,method = kz_term:to_lower_binary(Method)
                         ,owner_id = kzd_devices:owner_id(AuthDoc)
                         ,password = get_auth_password(AuthDoc)
                         ,realm = Realm
                         ,register_overwrite_notify = kzd_devices:register_overwrite_notify(AuthDoc)
                         ,request=AuthnReq
                         ,suppress_unregister_notifications = kzd_devices:suppress_unregister_notifications(AuthDoc)
                         ,username = Username
                         },
    maybe_auth_method(add_account_name(AuthUser), AuthDoc, AuthnReq, Method).

get_auth_password(AuthDoc) ->
    get_auth_password(kz_doc:type(AuthDoc), AuthDoc).

get_auth_password(<<"device">>, AuthDoc) ->
    kzd_devices:sip_password(AuthDoc, kz_binary:rand_hex(6));
get_auth_password(<<"trunk_server">>, AuthDoc) ->
    kzd_trunkserver:auth_password(AuthDoc, kz_binary:rand_hex(6)).

-spec get_auth_type(kz_json:object()) -> kz_term:ne_binary().
get_auth_type(AuthDoc) ->
    get_auth_type(kz_doc:type(AuthDoc), AuthDoc).

get_auth_type(<<"device">>, AuthDoc) ->
    get_device_auth_type(AuthDoc);
get_auth_type(_Other, AuthDoc) ->
    kz_doc:type(AuthDoc, <<"anonymous">>).

get_device_auth_type(AuthDoc) ->
    case kzd_devices:device_type(AuthDoc) of
        <<"mobile">> -> <<"mobile">>;
        _Other -> <<"device">>
    end.

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
get_auth_method(AuthDoc) ->
    get_auth_method(kz_doc:type(AuthDoc), AuthDoc).

get_auth_method(<<"device">>, AuthDoc) ->
    get_auth_device_type_method(get_device_auth_type(AuthDoc), AuthDoc);
get_auth_method(<<"trunk_server">>, AuthDoc) ->
    kzd_trunkserver:auth_method(AuthDoc).

get_auth_device_type_method(<<"mobile">>, AuthDoc) ->
    case kz_json:get_ne_binary_value([<<"gsm">>, <<"method">>], AuthDoc) of
        'undefined' -> kzd_devices:sip_method(AuthDoc);
        GSMMethod -> GSMMethod
    end;
get_auth_device_type_method(_Other, AuthDoc) ->
    kzd_devices:sip_method(AuthDoc).

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

-spec maybe_check_emergency_address(auth_response(), kapi_authn:req()) -> auth_response().
maybe_check_emergency_address(AuthResp, AuthnReq) ->
    maybe_check_emergency_address(AuthResp, AuthnReq, ?CHECK_DEVICE_EMERGENCY_ADDRESS).

%%------------------------------------------------------------------------------
%% @doc If expected to be set, and not emergency address is found, deny registration.
%% @end
%%------------------------------------------------------------------------------
-spec maybe_check_emergency_address(auth_response(), kapi_authn:req(), boolean()) -> auth_response().
maybe_check_emergency_address({'ok', #auth_user{doc=Doc}} = Ret, _AuthnReq, 'true') ->
    case kzd_devices:addresses_emergency(Doc) of
        'undefined' -> {'error', 'missing_emergency_address'};
        _Address -> Ret
    end;
maybe_check_emergency_address(AuthResp, _AuthnReq, _) ->
    AuthResp.

%%------------------------------------------------------------------------------
%% @doc If device_type=softphone or any integration services device type, some
%% checks are performed. If softphone, Kazoo needs to check the register request
%% is not from an integration service (integration_as_softphone). If not softphone
%% but an actual integration service; request's User Agent needs to be whitelisted
%% via User Agent regexes list (request_user_agent) and also the request's source
%% IP needs to be whitelisted as well and not denied (request_source_ip).
%% @end
%%------------------------------------------------------------------------------
-spec maybe_perform_integration_device_checks(auth_response(), kapi_authn:req()) -> auth_response().
maybe_perform_integration_device_checks({'ok', #auth_user{doc=Doc}} = Ret, AuthnReq) ->
    DeviceType = kzd_devices:device_type(Doc),
    case lists:member(DeviceType, [<<"softphone">> | ?INTEGRATION_DEVICE_TYPES]) of
        'false' ->
            lager:debug("not a softphone nor an integration-service device, not need to run checks"),
            Ret;
        'true' ->
            perform_integration_device_checks(Ret, AuthnReq, DeviceType)
    end;
maybe_perform_integration_device_checks({'error', _Reason} = AuthFailed, _AuthnReq) ->
    AuthFailed.

perform_integration_device_checks(Ret, AuthnReq, DeviceType) ->
    lager:debug("~s device trying to register, running checks", [DeviceType]),
    SourceIP = kz_json:get_ne_binary_value(<<"Orig-IP">>, AuthnReq),
    UserAgent = kz_json:get_ne_binary_value(<<"User-Agent">>, AuthnReq),
    UARegexes = kapps_config:get_ne_binaries(?CONFIG_CAT, <<"integrations_user_agent_regexes">>, []),
    {'ok', MP} = re:compile(kz_binary:join(UARegexes, <<"|">>)), %% Results in something like {ok, <<"regex1|regex2|regexn">>}.
    %% If any of the checks fail, the remaining ones are not executed.
    Checks = [fun check_integration_as_softphone/5 %% if integration_as_softphone, maybe migrate, maybe forbid registration.
             ,fun check_request_user_agent/5 %% if not softphone, check user agent (integration service) is whitelisted.
             ,fun check_request_source_ip/5 %% check request's source IP is allowed and not denied to register.
             ],
    lists:foldl(fun(F, Acc) -> F(Acc, DeviceType, SourceIP, UserAgent, MP) end, Ret, Checks).

%%------------------------------------------------------------------------------
%% @doc Checks if credentials from a softphone device are being used to REGISTER an "integration"
%% (MS Teams, residential, etc) device, which is forbidden.
%%
%% `NOTE': Temporarily (this exception may be removed in the future) maybe allowing this behavior,
%% depends on ?MIGRATE_SOFTPHONE_TO_MS_TEAMS configuration value.
%%
%% When device_type = `softphone' and request's User-Agent matches any of the integration services'
%% user-agent regexes:
%% - if(?MIGRATE_SOFTPHONE_TO_MS_TEAMS) -> migrate softphone to a proper MS-Teams device.
%% - else -> forbid registration.
%% @end
%%------------------------------------------------------------------------------
-spec check_integration_as_softphone(auth_response(), kz_term:ne_binary(), kz_term:ne_binary(), kz_term:ne_binary(), binary()) -> auth_response().
check_integration_as_softphone({'ok', _AuthUser} = Ret, <<"softphone">>, _SourceIP, 'undefined', _CompiledRegex) ->
    %% User-Agent is not a required header, so it may be missing in some requests.
    Ret;
check_integration_as_softphone({'ok', _AuthUser} = Ret, <<"softphone">>, _SourceIP, UserAgent, CompiledRegex) ->
    lager:debug("checking if user agent (~s) is not from an integration service", [UserAgent]),
    case re:run(UserAgent, CompiledRegex, ['notempty']) of
        {'match', _} ->
            maybe_migrate_softphone_to_ms_teams(Ret, UserAgent);
        'nomatch' ->
            lager:debug("'~s' seems to be a regular softphone client, continue", [UserAgent]),
            Ret
    end;
check_integration_as_softphone({'ok', _AuthUser} = Ret, _IntegrationDevice, _SourceIP, _UserAgent, _CompiledRegex) ->
    lager:debug("integration device '~s' not using a softphone to register, continue", [_IntegrationDevice]),
    Ret;
check_integration_as_softphone({'error', _Reason} = AuthFailed, _DeviceType, _SourceIP, _UserAgent, _CompiledRegex) ->
    AuthFailed.

-spec maybe_migrate_softphone_to_ms_teams(auth_response(), kz_term:ne_binary()) -> auth_response().
maybe_migrate_softphone_to_ms_teams({'ok', _AuthUser} = Ret, UserAgent) ->
    maybe_migrate_softphone_to_ms_teams(Ret, UserAgent, ?MIGRATE_SOFTPHONE_TO_MS_TEAMS).

-spec maybe_migrate_softphone_to_ms_teams(auth_response(), kz_term:ne_binary(), boolean()) -> auth_response().
maybe_migrate_softphone_to_ms_teams({'ok', #auth_user{doc=Doc}=AuthUser}, _UserAgent, 'true') ->
    lager:debug("migrating softphone (~s) to MS Teams integration device", [_UserAgent]),
    case do_migrate_softphone_to_ms_teams({'ok', Doc}) of
        {'ok', NewDoc} ->
            {'ok', AuthUser#auth_user{doc = NewDoc}};
        {'error', _Err} ->
            lager:info("failed to migrate device: ~p", [_Err]),
            {'error', 'integration_as_softphone'}
    end;
maybe_migrate_softphone_to_ms_teams({'ok', _AuthUser}, _UserAgent, 'false') ->
    lager:debug("trying to register '~s' integration device as a softphone, forbidden", [_UserAgent]),
    {'error', 'integration_as_softphone'}.

-spec do_migrate_softphone_to_ms_teams({'ok', kz_json:object()}) ->
          {'ok', kz_json:object()} | {'error', any()}.
do_migrate_softphone_to_ms_teams({'ok', _DevDoc} = Dev) ->
    do_migrate_softphone_to_ms_teams(Dev, 0, 3).

-spec do_migrate_softphone_to_ms_teams({'ok', kz_json:object()}, 0..3, 0..3) ->
          {'ok', kz_json:object()} | {'error', 'unable_to_migrate'}.
do_migrate_softphone_to_ms_teams({'ok', Doc} = Dev, Try, MaxTries)
  when Try < MaxTries ->
    DocId = kz_doc:id(Doc),
    AccountId = kz_doc:account_id(Doc),
    MSTeamsDefaults = ms_teams_device_defaults(),
    MSTeamsType = kzd_devices:device_type(MSTeamsDefaults),
    MSTeamsDoc = kz_json:merge(Doc, MSTeamsDefaults),
    case kz_datamgr:save_doc(kz_doc:account_db(Doc), MSTeamsDoc) of
        {'ok', NewDoc} ->
            lager:info("softphone ~s/~s migrated to ~s successfully", [AccountId, DocId, MSTeamsType]),
            {'ok', NewDoc};
        Err ->
            lager:debug("(~p/~p) failed to migrate softphone ~s/~s to ~s with error: ~p",
                        [Try+1, MaxTries, AccountId, DocId, MSTeamsType, Err]),
            %% Teammate may try to register (migrate) all the devices at the same time because it
            %% performs registrations every once in a while, so, sleeping at random times may give
            %% the db a rest between migrations.
            timer:sleep(rand:uniform(200)), %% sleep between 1-200 milliseconds.
            do_migrate_softphone_to_ms_teams(Dev, Try+1, MaxTries)
    end;
do_migrate_softphone_to_ms_teams({'ok', _AuthUser}, MaxTries, MaxTries) ->
    lager:warning("unable to migrate after ~p tries, forbid registration", [MaxTries]),
    {'error', 'unable_to_migrate'}.

-spec ms_teams_device_defaults() -> kz_json:object().
ms_teams_device_defaults() ->
    Fns = [{fun kzd_devices:set_media/2, ms_teams_device_default_media()}
          ,{fun kzd_devices:set_caller_id_options/2, ms_teams_device_default_caller_id_options()}
          ,{fun kzd_devices:set_sip_ignore_completed_elsewhere/2, 'false'}
          ,{fun kzd_devices:set_device_type/2, <<"teammate">>}
          ],
    kz_json:exec_first(Fns, kz_json:new()).

-spec ms_teams_device_default_media() -> kz_json:object().
ms_teams_device_default_media() ->
    kz_json:from_list_recursive([{<<"audio">>
                                 ,[{<<"codecs">>, [<<"PCMU">>, <<"PCMA">>]}]
                                 }
                                ,{<<"encryption">>
                                 ,[{<<"enforce_security">>, 'true'}
                                  ,{<<"methods">>, [<<"srtp">>]}
                                  ]
                                 }
                                ,{<<"video">>
                                 ,[{<<"codecs">>, []}]
                                 }
                                ,{<<"webrtc">>, 'false'}
                                ]
                               ,#{ascii_list_enforced => 'false'}
                               ).

-spec ms_teams_device_default_caller_id_options() -> kz_json:object().
ms_teams_device_default_caller_id_options() ->
    kz_json:from_list([{<<"outbound_privacy">>, <<"none">>}
                      ]).

%%------------------------------------------------------------------------------
%% @doc If device_type=softphone and it is not an intent to use a softphone device
%% to register an integration service device, let it continue without checking UA.
%%
%% If not a softphone, it is an integration service device, check its UA matches
%% any of the user agent regexes within the configuration.
%% @end
%%------------------------------------------------------------------------------
-spec check_request_user_agent(auth_response(), kz_term:ne_binary(), kz_term:ne_binary(), kz_term:ne_binary(), binary()) -> auth_response().
check_request_user_agent(Ret, <<"softphone">>, _SourceIP, _UserAgent, _CompiledRegex) ->
    %% Only check User Agent for integration services devices.
    Ret;
check_request_user_agent({'ok', _AuthUser} = Ret, _DeviceType, _SourceIP, 'undefined', _CompiledRegex) ->
    %% Same as `check_integration_as_softphone/5' function clause when DeviceType=:=<<"softphone">> and
    %% 'undefined'=:=UserAgent.
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
%% @doc If user_auth was successful, and device_type is "teammate" and source_ip is
%% allowed and not on the denied list, allow the registration, otherwise, deny the
%% registration.
%% @end
%%------------------------------------------------------------------------------
-spec check_request_source_ip(auth_response(), kz_term:ne_binary(), kz_term:ne_binary(), kz_term:ne_binary(), binary()) -> auth_response().
check_request_source_ip({'ok', _AuthUser} = Ret, <<"softphone">>, _SourceIP, _UserAgent, _CompiledRegex) ->
    %% Only check Source IP for integration services devices.
    Ret;
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

%%------------------------------------------------------------------------------
%% @doc Returns the ACL for the given Authorizing/Device Type.
%% @end
%%------------------------------------------------------------------------------
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
maybe_msisdn_from_callflows(#auth_user{account_db=AccountDb}=AuthUser
                           ,Type
                           ,Id
                           ) ->
    ViewOptions = [{'startkey', [Type, Id]}
                  ,{'endkey', [Type, Id, <<"9999999">>]}
                  ],
    case kz_datamgr:get_results(AccountDb, <<"callflows/msisdn">>, ViewOptions) of
        {'error', _R} ->
            lager:warning("failed to look up msisdn  in ~s: ~p", [AccountDb, _R]),
            AuthUser;
        {'ok', []} ->
            lager:debug("msisdn not found for ~s@~s in ~s", [Type, Id, AccountDb]),
            AuthUser;
        {'ok', [User|_]} ->
            MSISDN = kz_json:get_value([<<"value">>,<<"msisdn">>], User),
            lager:debug("found msisdn ~s for ~s@~s in account db: ~s"
                       ,[MSISDN, Type, Id, AccountDb]
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
get_account_id(AuthnDoc) -> kz_doc:account_id(AuthnDoc).

-spec get_account_db(kz_json:object()) -> kz_term:api_binary().
get_account_db(AuthnDoc) -> kz_doc:account_db(AuthnDoc).


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
