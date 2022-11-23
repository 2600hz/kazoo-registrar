# MS-Teams Integration

MS-Teams devices are able to connect to Kazoo via integration services. At the beginning, softphone
devices were allowed to be used for this purpose, but not anymore. This is because there are now
proper ms-teams integration devices implemented in Kazoo, and from now on, those should be used
instead.

So, when a request comes into `reg_authn_req:handle_req/2` and once the credentials have been used
to load the device's information, some checks will be performed to this device, ONLY if *device_type*'s
value is equal to any of `[<<"softphone">> | kapps_config:get_ne_binaries(<<"registrar">>, <<"integration_device_types">>, [<<"teammate">>])]`
resulting list's values.

There are 3 main checks implemented, they all have arity 5, and the parameters being passed to them
are: `(Accumulator, DeviceType, SourceIP, UserAgent, ListOfUserAgentRegexes)`.

Checks:

- **check_integration_as_softphone:** Checks if credentials from a softphone device are being used to
REGISTER an "integration" (MS Teams, residential, etc) device, if so, if
`kapps_config:get_boolean(<<"registrar">>, <<"migrate_softphone_to_ms_teams">>, 'false')` is _true_,
the device will be migrated to a proper Kazoo MS-Teams integration device. If _migration_ is
disabled, the registration will be rejected. If not softphone credentials, move to next check.
- **check_request_user_agent:** If *device_type=softphone* and it is not an intent to use a softphone
device to register an integration service device, let it continue without checking UA. Otherwise,
check its User Agent matches any of the user agent regexes (fifth parameter), if so, check will pass,
otherwise, request will be rejected.
- **check_request_source_ip:** If previous checks passed, device_type is any of the allowed Kazoo
integration device types, and source_ip is allowed AND not denied in ACL, allow the registration,
otherwise, deny the registration. The ACL is loaded per DeviceType.

For *check_request_source_ip* check, a new ACL was implemented under `registrar`'s application
category. Its content can be seen by running `kapps_config:get_json(<<"registrar">>, <<"access_control">>)`.
It will return a JSON structure where its root level keys are DeviceTypes. The full structure is
something like:

```erlang
ACL = kz_json:from_list_recursive([{DeviceType, [{<<"allow">>, AllowedIPsList}
                                                ,{<<"deny">>, DeniedIPsList}
                                                ]}
                                  ]).
```

There is also a default ACL that will be used when the given DeviceType does not have a configured
ACL, yet:

```erlang
DefaultACL = kz_json:from_list_recursive([{<<"default">>, [{<<"allow">>, []}
                                                          ,{<<"deny">>, []}
                                                          ]}
                                         ]).
```
