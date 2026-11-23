-module(lote_client_ip_ffi).

-export([
    parse_canonical/1,
    rate_limit_bucket/1
]).

parse_canonical(Bin) when is_binary(Bin) ->
    case parse_ip(Bin) of
        {ok, {ipv4, Addr}} -> {ok, format_ip(Addr)};
        {ok, {ipv6, Addr}} -> {ok, format_ip(Addr)};
        error -> {error, nil}
    end.

rate_limit_bucket(Bin) when is_binary(Bin) ->
    case parse_ip(Bin) of
        {ok, {ipv4, Addr}} ->
            {ok, <<(format_ip(Addr))/binary, "/32">>};
        {ok, {ipv6, {H1, H2, H3, H4, _H5, _H6, _H7, _H8}}} ->
            Masked = {H1, H2, H3, H4, 0, 0, 0, 0},
            {ok, <<(format_ip(Masked))/binary, "/64">>};
        error ->
            {error, nil}
    end.

parse_ip(Bin) ->
    case unicode:characters_to_list(Bin) of
        Chars when is_list(Chars) ->
            case is_ascii(Chars) of
                true ->
                    case inet:parse_strict_address(Chars) of
                        {ok, {A, B, C, D}} ->
                            {ok, {ipv4, {A, B, C, D}}};
                        {ok, {0, 0, 0, 0, 0, 16#FFFF, Hi, Lo}} ->
                            {ok,
                                {ipv4,
                                    {Hi bsr 8, Hi band 16#FF, Lo bsr 8,
                                        Lo band 16#FF}}};
                        {ok, {H1, H2, H3, H4, H5, H6, H7, H8}} ->
                            {ok, {ipv6, {H1, H2, H3, H4, H5, H6, H7, H8}}};
                        {error, _} ->
                            error
                    end;
                false ->
                    error
            end;
        _ ->
            error
    end.

is_ascii([]) -> true;
is_ascii([C | Rest]) when C >= 0, C =< 127 -> is_ascii(Rest);
is_ascii(_) -> false.

format_ip(Addr) ->
    unicode:characters_to_binary(string:lowercase(inet:ntoa(Addr))).
