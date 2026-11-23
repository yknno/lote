-module(lote_pubsub_ffi).

-export([
    clear_saved_subscribers/1,
    delete_saved_subscriber/2,
    load_saved_subscribers/1,
    save_subscriber/2,
    spawn_listener/2,
    start_and_listen/2
]).

-include_lib("pog/include/pog_Config.hrl").

-define(SUBSCRIBER_ETS_TABLE, lote_pubsub_subscribers).

ensure_subscriber_table() ->
    case ets:whereis(?SUBSCRIBER_ETS_TABLE) of
        undefined ->
            Owner =
                case whereis(init) of
                    undefined -> self();
                    InitPid -> InitPid
                end,
            try
                ets:new(?SUBSCRIBER_ETS_TABLE, [
                    named_table,
                    public,
                    bag,
                    {heir, Owner, none},
                    {read_concurrency, true},
                    {write_concurrency, true}
                ])
            catch
                error:badarg ->
                    ?SUBSCRIBER_ETS_TABLE
            end;
        _Tid ->
            ?SUBSCRIBER_ETS_TABLE
    end.

save_subscriber(Name, Subscriber) ->
    ensure_subscriber_table(),
    ets:insert(?SUBSCRIBER_ETS_TABLE, {Name, Subscriber}),
    nil.

delete_saved_subscriber(Name, Subscriber) ->
    ensure_subscriber_table(),
    ets:delete_object(?SUBSCRIBER_ETS_TABLE, {Name, Subscriber}),
    nil.

clear_saved_subscribers(Name) ->
    ensure_subscriber_table(),
    ets:delete(?SUBSCRIBER_ETS_TABLE, Name),
    nil.

load_saved_subscribers(Name) ->
    ensure_subscriber_table(),
    [Subscriber || {_Key, Subscriber} <- ets:lookup(?SUBSCRIBER_ETS_TABLE, Name)].

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

%% Asynchronously spawns a dedicated Postgres LISTEN worker for `Owner` (self()).
%% Never blocks the calling actor: when the worker finishes connecting and
%% executing `LISTEN <channel>`, it sends `{listener_connected, Pid, Channel}`
%% to `Owner`; if connecting or `LISTEN` fails, it sends
%% `{listener_connect_failed, Pid, Channel, ErrorBin}` and exits normally.
spawn_listener(Config, Channel) ->
    case validate_channel_identifier(Channel) of
        ok ->
            Owner = self(),
            Options = build_options(Config),
            Pid = spawn(fun() -> async_listener_init(Owner, Options, Channel) end),
            {ok, Pid};
        {error, Reason} ->
            {error, Reason}
    end.

start_and_listen(Config, Channel) ->
    case validate_channel_identifier(Channel) of
        ok ->
            Owner = self(),
            Options = build_options(Config),
            InitRef = make_ref(),
            Pid = spawn(fun() -> sync_listener_init(Owner, InitRef, Options, Channel) end),
            MonRef = erlang:monitor(process, Pid),
            receive
                {InitRef, ok} ->
                    erlang:demonitor(MonRef, [flush]),
                    {ok, Pid};
                {InitRef, {error, Reason}} ->
                    erlang:demonitor(MonRef, [flush]),
                    {error, format_error(Reason)};
                {'DOWN', MonRef, process, Pid, Reason} ->
                    {error, format_error(Reason)}
            after 4000 ->
                erlang:demonitor(MonRef, [flush]),
                exit(Pid, kill),
                {error, <<"timed out starting Postgres LISTEN connection">>}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

validate_channel_identifier(Channel) when is_binary(Channel), byte_size(Channel) > 0, byte_size(Channel) =< 63 ->
    case is_valid_ident_bytes(Channel, true) of
        true -> ok;
        false -> {error, <<"invalid Postgres LISTEN channel identifier">>}
    end;
validate_channel_identifier(_) ->
    {error, <<"invalid Postgres LISTEN channel identifier">>}.

is_valid_ident_bytes(<<>>, _IsFirst) ->
    true;
is_valid_ident_bytes(<<C, Rest/binary>>, true)
  when (C >= $a andalso C =< $z) orelse (C >= $A andalso C =< $Z) orelse C =:= $_ ->
    is_valid_ident_bytes(Rest, false);
is_valid_ident_bytes(<<C, Rest/binary>>, false)
  when (C >= $a andalso C =< $z)
       orelse (C >= $A andalso C =< $Z)
       orelse (C >= $0 andalso C =< $9)
       orelse C =:= $_ ->
    is_valid_ident_bytes(Rest, false);
is_valid_ident_bytes(_, _) ->
    false.

build_options(Config) ->
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
    case Password of
        {some, Pw} -> maps:put(password, binary_to_list(Pw), Options1);
        none -> Options1
    end.

async_listener_init(Owner, Options, Channel) ->
    process_flag(trap_exit, true),
    OwnerRef = erlang:monitor(process, Owner),
    case open_and_listen(Options, Channel) of
        {ok, Conn} ->
            ListenRef = make_ref(),
            Owner ! {listener_connected, self(), Channel},
            listen_loop(Owner, OwnerRef, ListenRef, Conn);
        {error, Reason} ->
            Owner ! {listener_connect_failed, self(), Channel, format_error(Reason)}
    end.

sync_listener_init(Owner, InitRef, Options, Channel) ->
    process_flag(trap_exit, true),
    OwnerRef = erlang:monitor(process, Owner),
    case open_and_listen(Options, Channel) of
        {ok, Conn} ->
            ListenRef = make_ref(),
            Owner ! {InitRef, ok},
            listen_loop(Owner, OwnerRef, ListenRef, Conn);
        {error, Reason} ->
            Owner ! {InitRef, {error, Reason}}
    end.

open_and_listen(Options, Channel) ->
    try pgo_handler:open(undefined, Options) of
        {ok, Conn} ->
            case pgo_handler:extended_query(Conn, [<<"LISTEN ">>, Channel], []) of
                #{command := listen} ->
                    {ok, Conn};
                Other ->
                    safe_close(Conn),
                    {error, {listen_failed, Other}}
            end;
        {error, Reason} ->
            {error, Reason}
    catch
        Class:Reason ->
            {error, {Class, Reason}}
    end.

listen_loop(Owner, OwnerRef, ListenRef, Conn) ->
    receive
        {tcp, Socket, Binary} ->
            case dispatch_active_data(Owner, ListenRef, Binary, Conn) of
                {ok, Conn1} ->
                    case inet:setopts(Socket, [{active, once}]) of
                        ok ->
                            listen_loop(Owner, OwnerRef, ListenRef, Conn1);
                        {error, _} ->
                            safe_close(Conn1)
                    end;
                {closed, Conn1} ->
                    safe_close(Conn1)
            end;
        {ssl, Socket, Binary} ->
            case dispatch_active_data(Owner, ListenRef, Binary, Conn) of
                {ok, Conn1} ->
                    case ssl:setopts(Socket, [{active, once}]) of
                        ok ->
                            listen_loop(Owner, OwnerRef, ListenRef, Conn1);
                        {error, _} ->
                            safe_close(Conn1)
                    end;
                {closed, Conn1} ->
                    safe_close(Conn1)
            end;
        {tcp_closed, _Socket} ->
            safe_close(Conn);
        {tcp_error, _Socket, _Reason} ->
            safe_close(Conn);
        {ssl_closed, _Socket} ->
            safe_close(Conn);
        {ssl_error, _Socket, _Reason} ->
            safe_close(Conn);
        {'EXIT', _Pid, _Reason} ->
            safe_close(Conn);
        {'DOWN', OwnerRef, process, Owner, _Reason} ->
            safe_close(Conn)
    end.

dispatch_active_data(Owner, ListenRef, Binary, Conn) ->
    Conn1 =
        pgo_handler:process_active_data(Binary, Conn, fun
            ({notification_response, _ProcId, Channel, Payload}) ->
                Owner ! {notification, self(), ListenRef, Channel, Payload};
            (_) ->
                ok
        end),
    %% In pgo 0.20.0 (pgo_internal.hrl), -record(conn, {owner, socket, socket_module, ...})
    %% stores `socket` at tuple position 3 (1 = 'conn', 2 = owner, 3 = socket) and sets it
    %% to `closed` when pgo_handler closes the socket on a framing/decode error.
    case element(3, Conn1) of
        closed -> {closed, Conn1};
        _ -> {ok, Conn1}
    end.

safe_close(Conn) ->
    try
        pgo_handler:close(Conn)
    catch
        _:_ -> ok
    end,
    ok.

format_error(Reason) ->
    list_to_binary(io_lib:format("~p", [Reason])).
