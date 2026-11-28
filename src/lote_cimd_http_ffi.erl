-module(lote_cimd_http_ffi).

-export([
    fetch_https/4,
    connect_and_fetch_tls/6,
    is_ip_literal/1,
    is_global_public_ip_string/1,
    parse_strict_metadata_json/1
]).

-define(FETCH_TIMEOUT_MS, 4000).
-define(MAX_HEADER_BYTES, 8192).
-define(MAX_CHUNK_LINE_BYTES, 256).
-define(MAX_TRAILER_BYTES, 4096).
-define(MAX_RESOLVED_IPS, 4).

fetch_https(HostBin, PortInt, PathBin, MaxBodyBytes)
    when is_binary(HostBin),
         is_integer(PortInt),
         is_binary(PathBin),
         is_integer(MaxBodyBytes),
         MaxBodyBytes > 0
->
    _ = application:ensure_all_started(ssl),
    DeadlineMs = erlang:monotonic_time(millisecond) + ?FETCH_TIMEOUT_MS,
    case validate_target(HostBin, PortInt, PathBin) of
        {error, Err} ->
            {error, Err};
        {ok, HostChars} ->
            case resolve_verified_public_ips(HostChars, DeadlineMs) of
                {error, Err} ->
                    {error, Err};
                {ok, Ips} ->
                    Cacerts = public_key:cacerts_get(),
                    connect_first_reachable(
                        Ips,
                        PortInt,
                        HostBin,
                        PathBin,
                        Cacerts,
                        MaxBodyBytes,
                        DeadlineMs
                    )
            end
    end.

connect_and_fetch_tls(IpTuple, PortInt, HostBin, PathBin, Cacerts, MaxBodyBytes) ->
    _ = application:ensure_all_started(ssl),
    DeadlineMs = erlang:monotonic_time(millisecond) + ?FETCH_TIMEOUT_MS,
    connect_and_fetch_tls_deadline(
        IpTuple,
        PortInt,
        HostBin,
        PathBin,
        Cacerts,
        MaxBodyBytes,
        DeadlineMs
    ).

is_ip_literal(HostBin) when is_binary(HostBin) ->
    Stripped = strip_trailing_dots(strip_brackets(HostBin)),
    case Stripped =:= <<>> of
        true ->
            false;
        false ->
            case binary:match(Stripped, <<":">>) of
                {_, _} ->
                    true;
                nomatch ->
                    case ascii_charlist(Stripped) of
                        {ok, Chars} ->
                            case inet:parse_strict_address(Chars) of
                                {ok, _} ->
                                    true;
                                {error, _} ->
                                    case inet:parse_address(Chars) of
                                        {ok, _} -> true;
                                        {error, _} -> is_numeric_last_label(Stripped)
                                    end
                            end;
                        error ->
                            false
                    end
            end
    end.

is_global_public_ip_string(IpBin) when is_binary(IpBin) ->
    Stripped = strip_brackets(IpBin),
    case ascii_charlist(Stripped) of
        {ok, Chars} ->
            case inet:parse_strict_address(Chars) of
                {ok, IpTuple} -> is_global_public_ip(IpTuple);
                {error, _} -> false
            end;
        error ->
            false
    end.

parse_strict_metadata_json(JsonBin) when is_binary(JsonBin) ->
    case is_valid_utf8(JsonBin) of
        false ->
            {error, <<"Client metadata document is not valid UTF-8">>};
        true ->
            case decode_strict_json_object(JsonBin) of
                {error, Reason} ->
                    {error, Reason};
                {ok, Obj} ->
                    extract_metadata_fields(Obj)
            end
    end.

%% Internal: Target & SSRF validation

validate_target(HostBin, PortInt, PathBin) ->
    case
        PortInt >= 1
        andalso PortInt =< 65535
        andalso HostBin =/= <<>>
        andalso is_valid_request_path(PathBin)
        andalso not has_ctl_or_space(HostBin)
    of
        false ->
            {error, {invalid_url, <<"Invalid HTTPS request target">>}};
        true ->
            case is_ip_literal(HostBin) orelse is_blocked_hostname(HostBin) of
                true ->
                    {error,
                        {blocked_address,
                            <<"IP literals and local hostnames are not permitted">>}};
                false ->
                    case is_valid_ascii_fqdn(HostBin) of
                        false ->
                            {error, {invalid_url, <<"Invalid HTTPS hostname">>}};
                        true ->
                            case ascii_charlist(HostBin) of
                                {ok, HostChars} -> {ok, HostChars};
                                error -> {error, {invalid_url, <<"Hostname must be ASCII">>}}
                            end
                    end
            end
    end.

is_valid_request_path(PathBin) ->
    byte_size(PathBin) >= 1
        andalso binary:first(PathBin) =:= $/
        andalso is_printable_ascii_no_space(PathBin).

is_printable_ascii_no_space(<<>>) ->
    true;
is_printable_ascii_no_space(<<C:8, Rest/binary>>) when C >= 16#21, C =< 16#7E ->
    is_printable_ascii_no_space(Rest);
is_printable_ascii_no_space(_) ->
    false.

is_valid_ascii_fqdn(HostBin) ->
    Len = byte_size(HostBin),
    case
        Len >= 1
        andalso Len =< 253
        andalso binary:first(HostBin) =/= $.
        andalso binary:last(HostBin) =/= $.
        andalso binary:match(HostBin, <<"..">>) =:= nomatch
    of
        false ->
            false;
        true ->
            Labels = binary:split(HostBin, <<".">>, [global]),
            length(Labels) >= 2
                andalso lists:all(fun is_valid_dns_label/1, Labels)
                andalso not is_numeric_last_label(HostBin)
    end.

is_valid_dns_label(Label) ->
    Len = byte_size(Label),
    Len >= 1
        andalso Len =< 63
        andalso binary:first(Label) =/= $-
        andalso binary:last(Label) =/= $-
        andalso is_dns_label_chars(Label).

is_dns_label_chars(<<>>) ->
    true;
is_dns_label_chars(<<C:8, Rest/binary>>)
    when (C >= $a andalso C =< $z)
         orelse (C >= $A andalso C =< $Z)
         orelse (C >= $0 andalso C =< $9)
         orelse C =:= $-
->
    is_dns_label_chars(Rest);
is_dns_label_chars(_) ->
    false.

is_blocked_hostname(HostBin) ->
    Lower = strip_trailing_dots(ascii_lowercase_bin(HostBin)),
    Lower =:= <<"localhost">>
        orelse binary:match(Lower, <<".">>) =:= nomatch
        orelse ends_with_bin(Lower, <<".localhost">>)
        orelse ends_with_bin(Lower, <<".local">>)
        orelse ends_with_bin(Lower, <<".internal">>)
        orelse ends_with_bin(Lower, <<".home.arpa">>).

resolve_verified_public_ips(HostChars, DeadlineMs) ->
    case remaining_ms(DeadlineMs) of
        Rem1 when Rem1 =< 0 ->
            {error, {timeout, <<>>}};
        Rem1 ->
            V4Res = inet:getaddrs(HostChars, inet, Rem1),
            V6Res =
                case remaining_ms(DeadlineMs) of
                    Rem2 when Rem2 > 0 -> inet:getaddrs(HostChars, inet6, Rem2);
                    _ -> {error, timeout}
                end,
            V4Ips =
                case V4Res of
                    {ok, L4} -> L4;
                    _ -> []
                end,
            V6Ips =
                case V6Res of
                    {ok, L6} -> L6;
                    _ -> []
                end,
            AllIps = V4Ips ++ V6Ips,
            case AllIps of
                [] ->
                    case V4Res =:= {error, timeout} orelse V6Res =:= {error, timeout} of
                        true -> {error, {timeout, <<>>}};
                        false -> {error, {dns_error, <<"DNS resolution failed">>}}
                    end;
                _ ->
                    UniqueIps = unique_list(AllIps),
                    case lists:all(fun is_global_public_ip/1, UniqueIps) of
                        true ->
                            {ok, lists:sublist(UniqueIps, ?MAX_RESOLVED_IPS)};
                        false ->
                            {error,
                                {blocked_address, <<"Resolved to non-public IP address">>}}
                    end
            end
    end.

is_global_public_ip({A, B, C, D})
    when is_integer(A), A >= 0, A =< 255,
         is_integer(B), B >= 0, B =< 255,
         is_integer(C), C >= 0, C =< 255,
         is_integer(D), D >= 0, D =< 255
->
    if
        A =:= 0 -> false;
        A =:= 10 -> false;
        A =:= 100, B >= 64, B =< 127 -> false;
        A =:= 127 -> false;
        A =:= 169, B =:= 254 -> false;
        A =:= 172, B >= 16, B =< 31 -> false;
        A =:= 192, B =:= 0, C =:= 0 -> false;
        A =:= 192, B =:= 0, C =:= 2 -> false;
        A =:= 192, B =:= 88, C =:= 99 -> false;
        A =:= 192, B =:= 168 -> false;
        A =:= 198, (B =:= 18 orelse B =:= 19) -> false;
        A =:= 198, B =:= 51, C =:= 100 -> false;
        A =:= 203, B =:= 0, C =:= 113 -> false;
        A >= 224 -> false;
        true -> true
    end;
is_global_public_ip({S1, S2, S3, S4, S5, S6, S7, S8})
    when is_integer(S1), S1 >= 0, S1 =< 16#FFFF,
         is_integer(S2), S2 >= 0, S2 =< 16#FFFF,
         is_integer(S3), S3 >= 0, S3 =< 16#FFFF,
         is_integer(S4), S4 >= 0, S4 =< 16#FFFF,
         is_integer(S5), S5 >= 0, S5 =< 16#FFFF,
         is_integer(S6), S6 >= 0, S6 =< 16#FFFF,
         is_integer(S7), S7 >= 0, S7 =< 16#FFFF,
         is_integer(S8), S8 >= 0, S8 =< 16#FFFF
->
    case (S1 band 16#E000) =:= 16#2000 of
        false ->
            false;
        true ->
            if
                S1 =:= 16#2001, S2 =< 16#01FF -> false;
                S1 =:= 16#2001, S2 =:= 16#0DB8 -> false;
                S1 =:= 16#2002 -> false;
                S1 =:= 16#3FFF, (S2 band 16#F000) =:= 0 -> false;
                true -> true
            end
    end;
is_global_public_ip(_) ->
    false.

%% Internal: TLS Connect & HTTP/1.1 Exchange

connect_first_reachable([IpTuple], PortInt, HostBin, PathBin, Cacerts, MaxBodyBytes, DeadlineMs) ->
    connect_and_fetch_tls_deadline(
        IpTuple,
        PortInt,
        HostBin,
        PathBin,
        Cacerts,
        MaxBodyBytes,
        DeadlineMs
    );
connect_first_reachable(
    [IpTuple | Rest],
    PortInt,
    HostBin,
    PathBin,
    Cacerts,
    MaxBodyBytes,
    DeadlineMs
) ->
    case
        connect_tls_socket(IpTuple, PortInt, HostBin, Cacerts, DeadlineMs)
    of
        {ok, Sock} ->
            exchange_on_socket(Sock, HostBin, PortInt, PathBin, MaxBodyBytes, DeadlineMs);
        {error, {timeout, _} = TimeoutErr} ->
            {error, TimeoutErr};
        {error, _FirstErr} ->
            connect_first_reachable(
                Rest,
                PortInt,
                HostBin,
                PathBin,
                Cacerts,
                MaxBodyBytes,
                DeadlineMs
            )
    end.

connect_and_fetch_tls_deadline(
    IpTuple,
    PortInt,
    HostBin,
    PathBin,
    Cacerts,
    MaxBodyBytes,
    DeadlineMs
) ->
    case
        PortInt >= 1
        andalso PortInt =< 65535
        andalso is_valid_ascii_fqdn(HostBin)
        andalso is_valid_request_path(PathBin)
    of
        false ->
            {error, {invalid_url, <<"Invalid HTTPS request target">>}};
        true ->
            case connect_tls_socket(IpTuple, PortInt, HostBin, Cacerts, DeadlineMs) of
                {ok, Sock} ->
                    exchange_on_socket(
                        Sock,
                        HostBin,
                        PortInt,
                        PathBin,
                        MaxBodyBytes,
                        DeadlineMs
                    );
                {error, Err} ->
                    {error, Err}
            end
    end.

connect_tls_socket(IpTuple, PortInt, HostBin, Cacerts, DeadlineMs) ->
    case ascii_charlist(HostBin) of
        error ->
            {error, {invalid_url, <<"Hostname must be ASCII">>}};
        {ok, HostChars} ->
            case remaining_ms(DeadlineMs) of
                Rem when Rem =< 0 ->
                    {error, {timeout, <<>>}};
                Rem ->
                    SslOpts = [
                        binary,
                        {active, false},
                        {packet, raw},
                        {log_level, none},
                        {send_timeout, Rem},
                        {send_timeout_close, true},
                        {verify, verify_peer},
                        {cacerts, Cacerts},
                        {server_name_indication, HostChars},
                        {customize_hostname_check, [
                            {match_fun, public_key:pkix_verify_hostname_match_fun(https)}
                        ]}
                    ],
                    case ssl:connect(IpTuple, PortInt, SslOpts, Rem) of
                        {ok, Sock} ->
                            {ok, Sock};
                        {error, timeout} ->
                            {error, {timeout, <<>>}};
                        {error, Reason} ->
                            {error, {tls_or_connect_error, format_reason(Reason)}}
                    end
            end
    end.

exchange_on_socket(Sock, HostBin, PortInt, PathBin, MaxBodyBytes, DeadlineMs) ->
    try
        HostHeader =
            case PortInt of
                443 -> HostBin;
                _ -> iolist_to_binary([HostBin, <<":">>, integer_to_binary(PortInt)])
            end,
        Req = [
            <<"GET ">>,
            PathBin,
            <<" HTTP/1.1\r\nHost: ">>,
            HostHeader,
            <<"\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\nUser-Agent: lote-cimd/1.0\r\n\r\n">>
        ],
        case ssl:send(Sock, Req) of
            ok ->
                read_http_response(Sock, MaxBodyBytes, DeadlineMs);
            {error, timeout} ->
                {error, {timeout, <<>>}};
            {error, Reason} ->
                {error, {tls_or_connect_error, format_reason(Reason)}}
        end
    after
        _ = ssl:close(Sock)
    end.

read_http_response(Sock, MaxBodyBytes, DeadlineMs) ->
    case read_until_headers_end(Sock, <<>>, DeadlineMs) of
        {error, Err} ->
            {error, Err};
        {ok, HeaderBlock, InitialBody} ->
            case parse_status_and_headers(HeaderBlock) of
                {error, Err} ->
                    {error, Err};
                {ok, Status, Headers} ->
                    case check_content_encoding(Headers) of
                        {error, Err} ->
                            {error, Err};
                        ok ->
                            case
                                read_response_body(
                                    Status,
                                    Headers,
                                    InitialBody,
                                    Sock,
                                    MaxBodyBytes,
                                    DeadlineMs
                                )
                            of
                                {error, Err} ->
                                    {error, Err};
                                {ok, BodyBin} ->
                                    ContentType = join_header_values(<<"content-type">>, Headers),
                                    CacheControlOpt =
                                        case get_header_values(<<"cache-control">>, Headers) of
                                            [] -> none;
                                            Vals -> {some, join_bins(Vals, <<", ">>)}
                                        end,
                                    {ok, {Status, ContentType, CacheControlOpt, BodyBin}}
                            end
                    end
            end
    end.

read_until_headers_end(Sock, Acc, DeadlineMs) ->
    case binary:match(Acc, <<"\r\n\r\n">>) of
        {Pos, 4} when Pos =< ?MAX_HEADER_BYTES ->
            HeaderBlock = binary:part(Acc, 0, Pos),
            RestLen = byte_size(Acc) - Pos - 4,
            InitialBody = binary:part(Acc, Pos + 4, RestLen),
            {ok, HeaderBlock, InitialBody};
        {Pos, 4} when Pos > ?MAX_HEADER_BYTES ->
            {error, {invalid_http_response, <<"HTTP response headers too large">>}};
        nomatch when byte_size(Acc) > ?MAX_HEADER_BYTES ->
            {error, {invalid_http_response, <<"HTTP response headers too large">>}};
        nomatch ->
            case recv_chunk(Sock, DeadlineMs) of
                {ok, Chunk} ->
                    read_until_headers_end(Sock, <<Acc/binary, Chunk/binary>>, DeadlineMs);
                {error, closed} ->
                    {error, {invalid_http_response, <<"Truncated HTTP response headers">>}};
                {error, Err} ->
                    {error, Err}
            end
    end.

parse_status_and_headers(HeaderBlock) ->
    case binary:split(HeaderBlock, <<"\r\n">>, [global]) of
        [StatusLine | RawHeaderLines] ->
            case parse_status_line(StatusLine) of
                {ok, Status} ->
                    case parse_header_lines(RawHeaderLines, []) of
                        {ok, Headers} -> {ok, Status, Headers};
                        {error, Err} -> {error, Err}
                    end;
                {error, Err} ->
                    {error, Err}
            end;
        [] ->
            {error, {invalid_http_response, <<"Empty HTTP response">>}}
    end.

parse_status_line(<<"HTTP/1.", Minor:8, " ", D1:8, D2:8, D3:8, Rest/binary>>)
    when (Minor =:= $0 orelse Minor =:= $1),
         D1 >= $0,
         D1 =< $9,
         D2 >= $0,
         D2 =< $9,
         D3 >= $0,
         D3 =< $9
->
    case Rest =:= <<>> orelse binary:first(Rest) =:= $\s of
        true ->
            Status = (D1 - $0) * 100 + (D2 - $0) * 10 + (D3 - $0),
            case Status >= 100 andalso Status =< 599 of
                true -> {ok, Status};
                false -> {error, {invalid_http_response, <<"Invalid HTTP status code">>}}
            end;
        false ->
            {error, {invalid_http_response, <<"Malformed HTTP status line">>}}
    end;
parse_status_line(_) ->
    {error, {invalid_http_response, <<"Malformed HTTP status line">>}}.

parse_header_lines([], AccRev) ->
    {ok, lists:reverse(AccRev)};
parse_header_lines([Line | Rest], AccRev) ->
    case binary:split(Line, <<":">>) of
        [RawName, RawVal] when RawName =/= <<>> ->
            case is_valid_header_name(RawName) of
                false ->
                    {error, {invalid_http_response, <<"Invalid HTTP header name">>}};
                true ->
                    case is_valid_header_value(RawVal) of
                        false ->
                            {error, {invalid_http_response, <<"Invalid HTTP header value">>}};
                        true ->
                            Name = ascii_lowercase_bin(RawName),
                            Val = trim_ows(RawVal),
                            parse_header_lines(Rest, [{Name, Val} | AccRev])
                    end
            end;
        _ ->
            {error, {invalid_http_response, <<"Malformed HTTP header line">>}}
    end.

is_valid_header_name(Bin) ->
    is_valid_header_name_bytes(Bin).

is_valid_header_name_bytes(<<>>) ->
    true;
is_valid_header_name_bytes(<<C:8, Rest/binary>>)
    when C >= $!,
         C =< $~,
         C =/= $:
->
    is_valid_header_name_bytes(Rest);
is_valid_header_name_bytes(_) ->
    false.

is_valid_header_value(<<>>) ->
    true;
is_valid_header_value(<<C:8, Rest/binary>>)
    when C =:= 16#09;
         (C >= 16#20 andalso C =< 16#7E)
->
    is_valid_header_value(Rest);
is_valid_header_value(_) ->
    false.

check_content_encoding(Headers) ->
    Vals = get_header_values(<<"content-encoding">>, Headers),
    Tokens = split_comma_tokens(Vals),
    case lists:all(fun(T) -> T =:= <<"identity">> end, Tokens) of
        true -> ok;
        false -> {error, {invalid_http_response, <<"Unsupported Content-Encoding">>}}
    end.

read_response_body(Status, _Headers, _InitialBody, _Sock, _MaxBodyBytes, _DeadlineMs)
    when Status < 200; Status =:= 204; Status =:= 304
->
    {ok, <<>>};
read_response_body(_Status, Headers, InitialBody, Sock, MaxBodyBytes, DeadlineMs) ->
    TeVals = get_header_values(<<"transfer-encoding">>, Headers),
    ClVals = get_header_values(<<"content-length">>, Headers),
    case {TeVals, ClVals} of
        {[_ | _], [_ | _]} ->
            {error,
                {invalid_http_response, <<"Conflicting Transfer-Encoding and Content-Length">>}};
        {[_ | _], []} ->
            case split_comma_tokens(TeVals) of
                [<<"chunked">>] ->
                    read_chunked_body(InitialBody, [], 0, Sock, MaxBodyBytes, DeadlineMs);
                _ ->
                    {error, {invalid_http_response, <<"Unsupported Transfer-Encoding">>}}
            end;
        {[], [_ | _]} ->
            case parse_single_content_length(ClVals) of
                {error, Err} ->
                    {error, Err};
                {ok, Len} when Len > MaxBodyBytes ->
                    {error, {response_too_large, <<>>}};
                {ok, Len} ->
                    read_exact_length(InitialBody, Len, Sock, DeadlineMs)
            end;
        {[], []} ->
            read_until_eof(InitialBody, Sock, MaxBodyBytes, DeadlineMs)
    end.

parse_single_content_length(ClVals) ->
    Tokens = split_comma_tokens(ClVals),
    case Tokens of
        [] ->
            {error, {invalid_http_response, <<"Empty Content-Length header">>}};
        _ ->
            case parse_non_neg_ints(Tokens, []) of
                error ->
                    {error, {invalid_http_response, <<"Invalid Content-Length header">>}};
                {ok, [First | Rest]} ->
                    case lists:all(fun(N) -> N =:= First end, Rest) of
                        true ->
                            {ok, First};
                        false ->
                            {error,
                                {invalid_http_response, <<"Conflicting Content-Length headers">>}}
                    end
            end
    end.

parse_non_neg_ints([], AccRev) ->
    {ok, lists:reverse(AccRev)};
parse_non_neg_ints([Bin | Rest], AccRev) ->
    case is_ascii_digits(Bin) of
        true ->
            parse_non_neg_ints(Rest, [binary_to_integer(Bin) | AccRev]);
        false ->
            error
    end.

read_exact_length(Buf, Len, _Sock, _DeadlineMs) when byte_size(Buf) >= Len ->
    {ok, binary:part(Buf, 0, Len)};
read_exact_length(Buf, Len, Sock, DeadlineMs) ->
    case recv_chunk(Sock, DeadlineMs) of
        {ok, Chunk} ->
            read_exact_length(<<Buf/binary, Chunk/binary>>, Len, Sock, DeadlineMs);
        {error, closed} ->
            {error, {invalid_http_response, <<"Truncated HTTP response body">>}};
        {error, Err} ->
            {error, Err}
    end.

read_until_eof(Buf, _Sock, MaxBodyBytes, _DeadlineMs) when byte_size(Buf) > MaxBodyBytes ->
    {error, {response_too_large, <<>>}};
read_until_eof(Buf, Sock, MaxBodyBytes, DeadlineMs) ->
    case recv_chunk(Sock, DeadlineMs) of
        {ok, Chunk} ->
            Next = <<Buf/binary, Chunk/binary>>,
            case byte_size(Next) > MaxBodyBytes of
                true -> {error, {response_too_large, <<>>}};
                false -> read_until_eof(Next, Sock, MaxBodyBytes, DeadlineMs)
            end;
        {error, closed} ->
            {ok, Buf};
        {error, Err} ->
            {error, Err}
    end.

read_chunked_body(Buf, ChunksRev, TotalBytes, Sock, MaxBodyBytes, DeadlineMs) ->
    case binary:match(Buf, <<"\r\n">>) of
        {Pos, 2} when Pos =< ?MAX_CHUNK_LINE_BYTES ->
            Line = binary:part(Buf, 0, Pos),
            AfterLine = binary:part(Buf, Pos + 2, byte_size(Buf) - Pos - 2),
            case parse_chunk_size(Line) of
                error ->
                    {error, {invalid_http_response, <<"Malformed chunk size">>}};
                {ok, 0} ->
                    case consume_chunk_trailers(AfterLine, Sock, DeadlineMs) of
                        ok -> {ok, iolist_to_binary(lists:reverse(ChunksRev))};
                        {error, Err} -> {error, Err}
                    end;
                {ok, ChunkSize} when TotalBytes + ChunkSize > MaxBodyBytes ->
                    {error, {response_too_large, <<>>}};
                {ok, ChunkSize} ->
                    case ensure_bytes(AfterLine, ChunkSize + 2, Sock, DeadlineMs) of
                        {error, Err} ->
                            {error, Err};
                        {ok, ReadyBuf} ->
                            case ReadyBuf of
                                <<ChunkData:ChunkSize/binary, "\r\n", RestBuf/binary>> ->
                                    read_chunked_body(
                                        RestBuf,
                                        [ChunkData | ChunksRev],
                                        TotalBytes + ChunkSize,
                                        Sock,
                                        MaxBodyBytes,
                                        DeadlineMs
                                    );
                                _ ->
                                    {error,
                                        {invalid_http_response,
                                            <<"Missing CRLF after chunk payload">>}}
                            end
                    end
            end;
        {Pos, 2} when Pos > ?MAX_CHUNK_LINE_BYTES ->
            {error, {invalid_http_response, <<"Chunk header line too long">>}};
        nomatch when byte_size(Buf) > ?MAX_CHUNK_LINE_BYTES ->
            {error, {invalid_http_response, <<"Chunk header line too long">>}};
        nomatch ->
            case recv_chunk(Sock, DeadlineMs) of
                {ok, More} ->
                    read_chunked_body(
                        <<Buf/binary, More/binary>>,
                        ChunksRev,
                        TotalBytes,
                        Sock,
                        MaxBodyBytes,
                        DeadlineMs
                    );
                {error, closed} ->
                    {error, {invalid_http_response, <<"Unexpected EOF in chunked body">>}};
                {error, Err} ->
                    {error, Err}
            end
    end.

parse_chunk_size(Line) ->
    [HexRaw | _] = binary:split(Line, <<";">>),
    Hex = trim_ows(HexRaw),
    case byte_size(Hex) >= 1 andalso byte_size(Hex) =< 8 andalso is_ascii_hex(Hex) of
        true -> {ok, binary_to_integer(Hex, 16)};
        false -> error
    end.

consume_chunk_trailers(<<"\r\n", _Rest/binary>>, _Sock, _DeadlineMs) ->
    ok;
consume_chunk_trailers(Buf, Sock, DeadlineMs) ->
    case binary:match(Buf, <<"\r\n\r\n">>) of
        {Pos, 4} when Pos =< ?MAX_TRAILER_BYTES ->
            ok;
        {Pos, 4} when Pos > ?MAX_TRAILER_BYTES ->
            {error, {invalid_http_response, <<"HTTP chunk trailers too large">>}};
        nomatch when byte_size(Buf) > ?MAX_TRAILER_BYTES ->
            {error, {invalid_http_response, <<"HTTP chunk trailers too large">>}};
        nomatch ->
            case recv_chunk(Sock, DeadlineMs) of
                {ok, More} ->
                    consume_chunk_trailers(<<Buf/binary, More/binary>>, Sock, DeadlineMs);
                {error, closed} ->
                    {error, {invalid_http_response, <<"Truncated HTTP chunk trailers">>}};
                {error, Err} ->
                    {error, Err}
            end
    end.

ensure_bytes(Buf, Needed, _Sock, _DeadlineMs) when byte_size(Buf) >= Needed ->
    {ok, Buf};
ensure_bytes(Buf, Needed, Sock, DeadlineMs) ->
    case recv_chunk(Sock, DeadlineMs) of
        {ok, More} ->
            ensure_bytes(<<Buf/binary, More/binary>>, Needed, Sock, DeadlineMs);
        {error, closed} ->
            {error, {invalid_http_response, <<"Truncated chunked HTTP body">>}};
        {error, Err} ->
            {error, Err}
    end.

recv_chunk(Sock, DeadlineMs) ->
    case remaining_ms(DeadlineMs) of
        Rem when Rem =< 0 ->
            {error, {timeout, <<>>}};
        Rem ->
            case ssl:recv(Sock, 0, Rem) of
                {ok, Data} -> {ok, Data};
                {error, closed} -> {error, closed};
                {error, timeout} -> {error, {timeout, <<>>}};
                {error, Reason} -> {error, {tls_or_connect_error, format_reason(Reason)}}
            end
    end.

remaining_ms(DeadlineMs) ->
    DeadlineMs - erlang:monotonic_time(millisecond).

%% Internal: Strict JSON Metadata Parsing

decode_strict_json_object(JsonBin) ->
    Push = fun(Key, Val, Acc) ->
        case maps:is_key(Key, Acc) of
            true -> erlang:error(duplicate_json_key);
            false -> Acc#{Key => Val}
        end
    end,
    Decoders = #{
        object_start => fun(_) -> #{} end,
        object_push => Push,
        object_finish => fun(Obj, OldAcc) -> {Obj, OldAcc} end
    },
    try json:decode(JsonBin, ok, Decoders) of
        {Obj, ok, <<>>} when is_map(Obj) ->
            {ok, Obj};
        _ ->
            {error, <<"Client metadata document must be a JSON object">>}
    catch
        error:duplicate_json_key ->
            {error, <<"Duplicate JSON member name in client metadata">>};
        _:_ ->
            {error, <<"Malformed JSON in client metadata document">>}
    end.

extract_metadata_fields(Obj) ->
    case maps:is_key(<<"client_secret">>, Obj) of
        true ->
            {error, <<"client_secret is forbidden in Client ID Metadata Documents">>};
        false ->
            case maps:is_key(<<"client_secret_expires_at">>, Obj) of
                true ->
                    {error,
                        <<"client_secret_expires_at is forbidden in Client ID Metadata Documents">>};
                false ->
                    case validate_optional_jwks(Obj) of
                        {error, Reason} ->
                            {error, Reason};
                        ok ->
                            case validate_none_auth_method(<<"revocation_endpoint_auth_method">>, Obj) of
                                {error, Reason} ->
                                    {error, Reason};
                                ok ->
                                    case
                                        validate_none_auth_method(
                                            <<"introspection_endpoint_auth_method">>, Obj
                                        )
                                    of
                                        {error, Reason} ->
                                            {error, Reason};
                                        ok ->
                                            extract_required_and_optional(Obj)
                                    end
                            end
                    end
            end
    end.

validate_optional_jwks(Obj) ->
    case maps:find(<<"jwks">>, Obj) of
        error ->
            ok;
        {ok, #{<<"keys">> := Keys}} when is_list(Keys) ->
            validate_jwk_entries(Keys);
        {ok, _} ->
            {error, <<"Invalid jwks field in Client ID Metadata Document">>}
    end.

validate_jwk_entries([]) ->
    ok;
validate_jwk_entries([KeyObj | Rest]) when is_map(KeyObj) ->
    HasSymmetricKty =
        case maps:find(<<"kty">>, KeyObj) of
            {ok, KtyBin} when is_binary(KtyBin) ->
                ascii_lowercase_bin(KtyBin) =:= <<"oct">>;
            {ok, _} ->
                true;
            error ->
                true
        end,
    ForbiddenMembers = [
        <<"d">>, <<"k">>, <<"p">>, <<"q">>, <<"dp">>, <<"dq">>, <<"qi">>, <<"oth">>
    ],
    HasPrivateMaterial = lists:any(
        fun(Member) -> maps:is_key(Member, KeyObj) end,
        ForbiddenMembers
    ),
    case HasSymmetricKty orelse HasPrivateMaterial of
        true ->
            {error,
                <<"Symmetric or private JWK material is forbidden in Client ID Metadata Documents">>};
        false ->
            validate_jwk_entries(Rest)
    end;
validate_jwk_entries(_) ->
    {error, <<"Each entry in jwks.keys must be a JSON object">>}.

validate_none_auth_method(FieldName, Obj) ->
    case maps:find(FieldName, Obj) of
        error ->
            ok;
        {ok, <<"none">>} ->
            ok;
        {ok, _} ->
            {error,
                <<"CIMD clients must use \"none\" for ", FieldName/binary>>}
    end.

extract_required_and_optional(Obj) ->
    case req_string_field(<<"client_id">>, Obj) of
        {error, Reason} ->
            {error, Reason};
        {ok, ClientIdBin} ->
            case req_string_list_field(<<"redirect_uris">>, Obj) of
                {error, Reason} ->
                    {error, Reason};
                {ok, RedirectUris} ->
                    case opt_string_field(<<"client_name">>, Obj) of
                        {error, Reason} ->
                            {error, Reason};
                        {ok, ClientNameOpt} ->
                            case opt_string_field(<<"application_type">>, Obj) of
                                {error, Reason} ->
                                    {error, Reason};
                                {ok, AppTypeOpt} ->
                                    case opt_string_field(<<"token_endpoint_auth_method">>, Obj) of
                                        {error, Reason} ->
                                            {error, Reason};
                                        {ok, TokenAuthOpt} ->
                                            case opt_string_list_field(<<"grant_types">>, Obj) of
                                                {error, Reason} ->
                                                    {error, Reason};
                                                {ok, GrantTypesOpt} ->
                                                    case
                                                        opt_string_list_field(
                                                            <<"response_types">>, Obj
                                                        )
                                                    of
                                                        {error, Reason} ->
                                                            {error, Reason};
                                                        {ok, ResponseTypesOpt} ->
                                                            case
                                                                opt_string_field(
                                                                    <<"scope">>, Obj
                                                                )
                                                            of
                                                                {error, Reason} ->
                                                                    {error, Reason};
                                                                {ok, ScopeOpt} ->
                                                                    {ok, {
                                                                        ClientIdBin,
                                                                        ClientNameOpt,
                                                                        AppTypeOpt,
                                                                        RedirectUris,
                                                                        TokenAuthOpt,
                                                                        GrantTypesOpt,
                                                                        ResponseTypesOpt,
                                                                        ScopeOpt
                                                                    }}
                                                            end
                                                    end
                                            end
                                    end
                            end
                    end
            end
    end.

req_string_field(Key, Obj) ->
    case maps:find(Key, Obj) of
        {ok, Val} when is_binary(Val) -> {ok, Val};
        error -> {error, <<"Missing required field: ", Key/binary>>};
        {ok, _} -> {error, <<"Field must be a string: ", Key/binary>>}
    end.

req_string_list_field(Key, Obj) ->
    case maps:find(Key, Obj) of
        {ok, List} when is_list(List), List =/= [] ->
            case lists:all(fun erlang:is_binary/1, List) of
                true -> {ok, List};
                false -> {error, <<"Field must be a non-empty array of strings: ", Key/binary>>}
            end;
        error ->
            {error, <<"Missing required field: ", Key/binary>>};
        {ok, _} ->
            {error, <<"Field must be a non-empty array of strings: ", Key/binary>>}
    end.

opt_string_field(Key, Obj) ->
    case maps:find(Key, Obj) of
        error -> {ok, none};
        {ok, Val} when is_binary(Val) -> {ok, {some, Val}};
        {ok, _} -> {error, <<"Field must be a string: ", Key/binary>>}
    end.

opt_string_list_field(Key, Obj) ->
    case maps:find(Key, Obj) of
        error ->
            {ok, none};
        {ok, List} when is_list(List) ->
            case lists:all(fun erlang:is_binary/1, List) of
                true -> {ok, {some, List}};
                false -> {error, <<"Field must be an array of strings: ", Key/binary>>}
            end;
        {ok, _} ->
            {error, <<"Field must be an array of strings: ", Key/binary>>}
    end.

%% Internal: Binary / String Utilities

is_valid_utf8(Bin) ->
    case unicode:characters_to_binary(Bin, utf8, utf8) of
        Valid when is_binary(Valid) -> Valid =:= Bin;
        _ -> false
    end.

strip_brackets(<<"[", Rest/binary>>) ->
    Len = byte_size(Rest),
    case Len > 0 andalso binary:last(Rest) =:= $] of
        true -> binary:part(Rest, 0, Len - 1);
        false -> Rest
    end;
strip_brackets(Bin) ->
    Bin.

strip_trailing_dots(<<>>) ->
    <<>>;
strip_trailing_dots(Bin) ->
    case binary:last(Bin) of
        $. -> strip_trailing_dots(binary:part(Bin, 0, byte_size(Bin) - 1));
        _ -> Bin
    end.

is_numeric_last_label(HostBin) ->
    Labels = binary:split(HostBin, <<".">>, [global]),
    case lists:last(Labels) of
        <<>> ->
            false;
        Last ->
            is_ascii_digits(Last)
                orelse
                (case Last of
                    <<"0x", Hex/binary>> -> Hex =/= <<>> andalso is_ascii_hex(Hex);
                    <<"0X", Hex/binary>> -> Hex =/= <<>> andalso is_ascii_hex(Hex);
                    _ -> false
                end)
    end.

ascii_charlist(Bin) ->
    ascii_charlist_loop(Bin, []).

ascii_charlist_loop(<<>>, AccRev) ->
    {ok, lists:reverse(AccRev)};
ascii_charlist_loop(<<C:8, Rest/binary>>, AccRev) when C >= 1, C =< 127 ->
    ascii_charlist_loop(Rest, [C | AccRev]);
ascii_charlist_loop(_, _) ->
    error.

has_ctl_or_space(<<>>) ->
    false;
has_ctl_or_space(<<C:8, _Rest/binary>>) when C =< 16#20; C =:= 16#7F ->
    true;
has_ctl_or_space(<<_:8, Rest/binary>>) ->
    has_ctl_or_space(Rest).

ascii_lowercase_bin(Bin) ->
    << <<(ascii_lower_byte(C)):8>> || <<C:8>> <= Bin >>.

ascii_lower_byte(C) when C >= $A, C =< $Z -> C + 32;
ascii_lower_byte(C) -> C.

ends_with_bin(Bin, Suffix) ->
    BLen = byte_size(Bin),
    SLen = byte_size(Suffix),
    BLen >= SLen andalso binary:part(Bin, BLen - SLen, SLen) =:= Suffix.

trim_ows(Bin) ->
    trim_ows_right(trim_ows_left(Bin)).

trim_ows_left(<<C:8, Rest/binary>>) when C =:= $\s; C =:= $\t ->
    trim_ows_left(Rest);
trim_ows_left(Bin) ->
    Bin.

trim_ows_right(<<>>) ->
    <<>>;
trim_ows_right(Bin) ->
    case binary:last(Bin) of
        C when C =:= $\s; C =:= $\t ->
            trim_ows_right(binary:part(Bin, 0, byte_size(Bin) - 1));
        _ ->
            Bin
    end.

get_header_values(Name, Headers) ->
    [Val || {K, Val} <- Headers, K =:= Name].

join_header_values(Name, Headers) ->
    case get_header_values(Name, Headers) of
        [] -> <<>>;
        Vals -> join_bins(Vals, <<", ">>)
    end.

join_bins([], _Sep) ->
    <<>>;
join_bins([Single], _Sep) ->
    Single;
join_bins([First | Rest], Sep) ->
    iolist_to_binary([First | [[Sep, Item] || Item <- Rest]]).

split_comma_tokens(Vals) ->
    lists:flatmap(
        fun(Val) ->
            Parts = binary:split(Val, <<",">>, [global]),
            [
                ascii_lowercase_bin(T)
             || P <- Parts,
                begin
                    T = trim_ows(P),
                    T =/= <<>>
                end
            ]
        end,
        Vals
    ).

is_ascii_digits(<<>>) ->
    false;
is_ascii_digits(Bin) ->
    is_ascii_digits_loop(Bin).

is_ascii_digits_loop(<<>>) ->
    true;
is_ascii_digits_loop(<<C:8, Rest/binary>>) when C >= $0, C =< $9 ->
    is_ascii_digits_loop(Rest);
is_ascii_digits_loop(_) ->
    false.

is_ascii_hex(<<>>) ->
    false;
is_ascii_hex(Bin) ->
    is_ascii_hex_loop(Bin).

is_ascii_hex_loop(<<>>) ->
    true;
is_ascii_hex_loop(<<C:8, Rest/binary>>)
    when (C >= $0 andalso C =< $9)
         orelse (C >= $a andalso C =< $f)
         orelse (C >= $A andalso C =< $F)
->
    is_ascii_hex_loop(Rest);
is_ascii_hex_loop(_) ->
    false.

unique_list(List) ->
    unique_list_loop(List, []).

unique_list_loop([], AccRev) ->
    lists:reverse(AccRev);
unique_list_loop([H | T], AccRev) ->
    case lists:member(H, AccRev) of
        true -> unique_list_loop(T, AccRev);
        false -> unique_list_loop(T, [H | AccRev])
    end.

format_reason(Reason) ->
    Chars = io_lib:format("~0p", [Reason]),
    case unicode:characters_to_binary(Chars) of
        Bin when is_binary(Bin) -> Bin;
        _ -> <<"TLS or connection error">>
    end.
