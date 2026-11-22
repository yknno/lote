-module(lote_pubsub_ffi).

-export([start_and_listen/2]).

-include_lib("pog/include/pog_Config.hrl").

default_ssl_options(Host, Ssl) ->
    case Ssl of
        ssl_disabled ->
            {false, []};
        ssl_unverified ->
            {true, [{verify, verify_none}]};
        ssl_verified ->
            {true, [
                {verify, verify_peer},
                {cacerts, public_key:cacerts_get()},
                {server_name_indication, binary_to_list(Host)},
                {customize_hostname_check, [
                    {match_fun, public_key:pkix_verify_hostname_match_fun(https)}
                ]}
            ]}
    end.

start_and_listen(Config, Channel) ->
    #config{
        host = Host,
        port = Port,
        database = Database,
        user = User,
        password = Password,
        ssl = Ssl,
        connection_parameters = ConnectionParameters,
        trace = Trace,
        ip_version = IpVersion
    } = Config,
    {SslActivated, SslOptions} = default_ssl_options(Host, Ssl),
    Options1 = #{
        host => binary_to_list(Host),
        port => Port,
        database => binary_to_list(Database),
        user => binary_to_list(User),
        ssl => SslActivated,
        ssl_options => SslOptions,
        connection_parameters => ConnectionParameters,
        trace => Trace,
        socket_options =>
            case IpVersion of
                ipv4 -> [];
                ipv6 -> [inet6]
            end
    },
    Options2 =
        case Password of
            {some, Pw} -> maps:put(password, binary_to_list(Pw), Options1);
            none -> Options1
        end,
    case pgo_notifications:start_link(Options2) of
        {ok, Pid} ->
            case pgo_notifications:listen(Pid, Channel) of
                {ok, _Ref} -> {ok, Pid};
                {eventually, _Ref} -> {ok, Pid};
                Error -> {error, list_to_binary(io_lib:format("~p", [Error]))}
            end;
        {error, Reason} ->
            {error, list_to_binary(io_lib:format("~p", [Reason]))}
    end.
