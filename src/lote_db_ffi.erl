-module(lote_db_ffi).

-export([is_single_connection/1]).

is_single_connection({single_connection, _}) ->
    true;
is_single_connection(_) ->
    false.
