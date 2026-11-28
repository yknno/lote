-module(lote_cimd_test_ffi).

-export([
    test_serve_tls_once/2,
    fetch_tls_pinned_for_test/6
]).

fetch_tls_pinned_for_test(IpBin, PortInt, SniHostBin, PathBin, Cacerts, MaxBodyBytes)
    when is_binary(IpBin),
         is_integer(PortInt),
         is_binary(SniHostBin),
         is_binary(PathBin),
         is_list(Cacerts),
         is_integer(MaxBodyBytes)
->
    _ = application:ensure_all_started(ssl),
    case unicode:characters_to_list(IpBin) of
        IpChars when is_list(IpChars) ->
            case inet:parse_strict_address(IpChars) of
                {ok, IpTuple} ->
                    lote_cimd_http_ffi:connect_and_fetch_tls(
                        IpTuple,
                        PortInt,
                        SniHostBin,
                        PathBin,
                        Cacerts,
                        MaxBodyBytes
                    );
                {error, _} ->
                    {error, {invalid_url, <<"Invalid test IP address">>}}
            end;
        _ ->
            {error, {invalid_url, <<"Invalid test IP address">>}}
    end.

test_serve_tls_once(CertDnsHostBin, RawHttpResponseBin)
    when is_binary(CertDnsHostBin), is_binary(RawHttpResponseBin)
->
    _ = application:ensure_all_started(ssl),
    DnsChars = unicode:characters_to_list(CertDnsHostBin),
    SanOid = {2, 5, 29, 17},
    KeyUsageOid = {2, 5, 29, 15},
    Curve = {namedCurve, {1, 2, 840, 10045, 3, 1, 7}},
    TestData = public_key:pkix_test_data(#{
        server_chain => #{
            root => [{digest, sha256}, {key, public_key:generate_key(Curve)}],
            intermediates => [],
            peer => [
                {digest, sha256},
                {key, public_key:generate_key(Curve)},
                {extensions, [
                    {'Extension', SanOid, false, [{dNSName, DnsChars}]},
                    {'Extension', KeyUsageOid, true, [digitalSignature]}
                ]}
            ]
        },
        client_chain => #{root => [], intermediates => [], peer => []}
    }),
    ServerConf0 = maps:get(server_config, TestData),
    ServerConf1 = proplists:delete(
        verify,
        proplists:delete(fail_if_no_peer_cert, ServerConf0)
    ),
    ServerConf = [
        binary,
        {active, false},
        {ip, {127, 0, 0, 1}},
        {reuseaddr, true},
        {verify, verify_none},
        {log_level, none}
        | ServerConf1
    ],
    ClientConf = maps:get(client_config, TestData),
    RootCerts = proplists:get_value(cacerts, ClientConf),
    {ok, ListenSock} = ssl:listen(0, ServerConf),
    {ok, {_, Port}} = ssl:sockname(ListenSock),
    spawn(fun() ->
        try
            case ssl:transport_accept(ListenSock, 3000) of
                {ok, TransSock} ->
                    case ssl:handshake(TransSock, 3000) of
                        {ok, TlsSock} ->
                            _ = ssl:recv(TlsSock, 0, 2000),
                            _ = ssl:send(TlsSock, RawHttpResponseBin),
                            _ = ssl:close(TlsSock);
                        {error, _} ->
                            _ = ssl:close(TransSock)
                    end;
                {error, _} ->
                    ok
            end
        after
            _ = ssl:close(ListenSock)
        end
    end),
    {Port, RootCerts}.
