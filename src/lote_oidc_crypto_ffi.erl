-module(lote_oidc_crypto_ffi).

-include_lib("public_key/include/public_key.hrl").

-export([
    generate_p256_key/0,
    default_ephemeral_p256_key/0,
    parse_signing_key_pem/1,
    parse_verify_keys_pem/1,
    sign_es256/2,
    verify_es256/4,
    export_private_key_pem/3,
    unix_now_seconds/0,
    validate_jws_header_json/1,
    validate_jwt_claims_json/1
]).

-define(P256_P,
    16#FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
).
-define(P256_B,
    16#5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
).
-define(P256_N,
    16#FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
).

generate_p256_key() ->
    {PubPoint, PrivScalar} = crypto:generate_key(ecdh, secp256r1),
    <<4, X:32/binary, Y:32/binary>> = PubPoint,
    PrivScalarBin = pad_scalar_32(PrivScalar),
    {PrivScalarBin, X, Y}.

default_ephemeral_p256_key() ->
    case persistent_term:get({lote_oidc, default_p256_key}, undefined) of
        undefined ->
            Key = generate_p256_key(),
            persistent_term:put({lote_oidc, default_p256_key}, Key),
            Key;
        Key ->
            Key
    end.

parse_signing_key_pem(PemBin) when is_binary(PemBin) ->
    case safe_pem_decode(PemBin) of
        {error, Reason} ->
            {error, Reason};
        {ok, RawEntries} ->
            case filter_ecpk_parameters(RawEntries, []) of
                {error, Reason} ->
                    {error, Reason};
                {ok, []} ->
                    {error, <<"No PEM entries found">>};
                {ok, [Entry]} ->
                    decode_signing_entry(Entry);
                {ok, [_ | _]} ->
                    {error, <<"PEM must contain exactly one private key">>}
            end
    end.

parse_verify_keys_pem(PemBin) when is_binary(PemBin) ->
    case safe_pem_decode(PemBin) of
        {error, Reason} ->
            {error, Reason};
        {ok, RawEntries} ->
            case filter_ecpk_parameters(RawEntries, []) of
                {error, Reason} ->
                    {error, Reason};
                {ok, []} ->
                    {error, <<"No PEM entries found">>};
                {ok, Entries} ->
                    decode_verify_entries(Entries, [])
            end
    end.

sign_es256(SigningInput, PrivScalarBin)
    when is_binary(SigningInput), is_binary(PrivScalarBin), byte_size(PrivScalarBin) =:= 32
->
    DerSig = crypto:sign(ecdsa, sha256, SigningInput, [PrivScalarBin, secp256r1]),
    #'ECDSA-Sig-Value'{r = R, s = S} = public_key:der_decode('ECDSA-Sig-Value', DerSig),
    <<R:256/big-unsigned-integer, S:256/big-unsigned-integer>>.

verify_es256(SigningInput, RawSig, XBin, YBin)
    when is_binary(SigningInput),
         is_binary(RawSig),
         is_binary(XBin),
         is_binary(YBin)
->
    case byte_size(RawSig) =:= 64 andalso is_valid_p256_point(XBin, YBin) of
        false ->
            false;
        true ->
            <<R:256/big-unsigned-integer, S:256/big-unsigned-integer>> = RawSig,
            case R >= 1 andalso R < ?P256_N andalso S >= 1 andalso S < ?P256_N of
                false ->
                    false;
                true ->
                    DerSig = public_key:der_encode(
                        'ECDSA-Sig-Value',
                        #'ECDSA-Sig-Value'{r = R, s = S}
                    ),
                    PubPoint = <<4, XBin:32/binary, YBin:32/binary>>,
                    crypto:verify(
                        ecdsa,
                        sha256,
                        SigningInput,
                        DerSig,
                        [PubPoint, secp256r1]
                    )
            end
    end.

export_private_key_pem(PrivScalarBin, XBin, YBin)
    when is_binary(PrivScalarBin),
         byte_size(PrivScalarBin) =:= 32,
         is_binary(XBin),
         byte_size(XBin) =:= 32,
         is_binary(YBin),
         byte_size(YBin) =:= 32
->
    PubPoint = <<4, XBin:32/binary, YBin:32/binary>>,
    Curve = {namedCurve, ?'secp256r1'},
    ECKey = #'ECPrivateKey'{
        version = 1,
        privateKey = PrivScalarBin,
        parameters = Curve,
        publicKey = PubPoint,
        attributes = asn1_NOVALUE
    },
    Sec1Entry = public_key:pem_entry_encode('ECPrivateKey', ECKey),
    Sec1Pem = iolist_to_binary(public_key:pem_encode([Sec1Entry])),
    Pkcs8Entry = public_key:pem_entry_encode('PrivateKeyInfo', ECKey),
    Pkcs8Pem = iolist_to_binary(public_key:pem_encode([Pkcs8Entry])),
    SpkiEntry = public_key:pem_entry_encode(
        'SubjectPublicKeyInfo',
        {#'ECPoint'{point = PubPoint}, Curve}
    ),
    SpkiPem = iolist_to_binary(public_key:pem_encode([SpkiEntry])),
    {Sec1Pem, Pkcs8Pem, SpkiPem}.

unix_now_seconds() ->
    erlang:system_time(second).

validate_jws_header_json(JsonBin) when is_binary(JsonBin) ->
    case decode_strict_json_object(JsonBin) of
        {ok, Map} ->
            case maps:is_key(<<"crit">>, Map) of
                true -> {error, <<"Unsupported critical JWS header extension">>};
                false -> {ok, nil}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

validate_jwt_claims_json(JsonBin) when is_binary(JsonBin) ->
    case decode_strict_json_object(JsonBin) of
        {ok, _Map} -> {ok, nil};
        {error, Reason} -> {error, Reason}
    end.

%% Internal helpers

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
            {error, <<"Expected top-level JSON object">>}
    catch
        error:duplicate_json_key ->
            {error, <<"Duplicate JSON member name">>};
        _:_ ->
            {error, <<"Malformed JSON">>}
    end.

safe_pem_decode(PemBin) ->
    Normalized = binary:replace(PemBin, [<<"\\r\\n">>, <<"\\n">>], <<"\n">>, [global]),
    try public_key:pem_decode(Normalized) of
        Entries when is_list(Entries) ->
            {ok, Entries}
    catch
        _:_ ->
            {error, <<"Malformed PEM encoding">>}
    end.

filter_ecpk_parameters([], AccRev) ->
    {ok, lists:reverse(AccRev)};
filter_ecpk_parameters([{'EcpkParameters', _Der, CipherInfo} | _Rest], _AccRev)
    when CipherInfo =/= not_encrypted
->
    {error, <<"Encrypted PEM keys are not supported">>};
filter_ecpk_parameters([{'EcpkParameters', ParamsDer, not_encrypted} | Rest], AccRev)
    when is_binary(ParamsDer), byte_size(ParamsDer) > 0
->
    try public_key:der_decode('EcpkParameters', ParamsDer) of
        {namedCurve, ?'secp256r1'} ->
            filter_ecpk_parameters(Rest, AccRev);
        _ ->
            {error, <<"Unsupported EC curve; expected P-256 (secp256r1)">>}
    catch
        _:_ ->
            {error, <<"Malformed EcpkParameters PEM entry">>}
    end;
filter_ecpk_parameters([{'EcpkParameters', <<>>, not_encrypted} | _Rest], _AccRev) ->
    {error, <<"Empty PEM key payload">>};
filter_ecpk_parameters([Entry | Rest], AccRev) ->
    filter_ecpk_parameters(Rest, [Entry | AccRev]).

decode_signing_entry({'EncryptedPrivateKeyInfo', _Der, _Cipher}) ->
    {error, <<"Encrypted PEM keys are not supported">>};
decode_signing_entry({_Type, _Der, CipherInfo}) when CipherInfo =/= not_encrypted ->
    {error, <<"Encrypted PEM keys are not supported">>};
decode_signing_entry({'ECPrivateKey', Der, not_encrypted} = Entry)
    when is_binary(Der), byte_size(Der) > 0
->
    try public_key:pem_entry_decode(Entry) of
        Decoded ->
            decode_private_key_record(Decoded)
    catch
        _:_ ->
            {error, <<"Malformed ASN.1 EC private key">>}
    end;
decode_signing_entry({'PrivateKeyInfo', Der, not_encrypted})
    when is_binary(Der), byte_size(Der) > 0
->
    decode_pkcs8_der(Der);
decode_signing_entry({_Type, <<>>, not_encrypted}) ->
    {error, <<"Empty PEM key payload">>};
decode_signing_entry({_Type, _Der, not_encrypted}) ->
    {error, <<"Unsupported PEM entry type; expected EC PRIVATE KEY or PRIVATE KEY">>}.

decode_pkcs8_der(Der) ->
    try 'PKCS-FRAME':decode('OneAsymmetricKey', Der) of
        {ok, {
            'OneAsymmetricKey',
            _Version,
            {'PrivateKeyAlgorithmIdentifier', ?'id-ecPublicKey', AlgParams},
            InnerDer,
            _Attributes,
            OuterMaybePub
        }} ->
            case decode_ec_alg_params(AlgParams) of
                {ok, OuterCurve} ->
                    InnerBin = to_binary(InnerDer),
                    try public_key:der_decode('ECPrivateKey', InnerBin) of
                        #'ECPrivateKey'{
                            privateKey = PrivOctets,
                            parameters = InnerParams,
                            publicKey = InnerMaybePub
                        } ->
                            case verify_combined_p256_curve(OuterCurve, InnerParams) of
                                true ->
                                    extract_validated_p256_key(
                                        PrivOctets,
                                        [InnerMaybePub, OuterMaybePub]
                                    );
                                false ->
                                    {error, <<"Unsupported EC curve; expected P-256 (secp256r1)">>}
                            end
                    catch
                        _:_ ->
                            {error, <<"Malformed inner ECPrivateKey in PKCS#8 key">>}
                    end;
                error ->
                    {error, <<"Unsupported EC curve; expected P-256 (secp256r1)">>}
            end;
        {ok, {'OneAsymmetricKey', _, _, _, _, _}} ->
            {error, <<"Unsupported private key algorithm; expected EC P-256">>};
        {error, _} ->
            {error, <<"Malformed ASN.1 PKCS#8 private key">>}
    catch
        _:_ ->
            {error, <<"Malformed ASN.1 PKCS#8 private key">>}
    end.

decode_private_key_record(#'ECPrivateKey'{
    privateKey = PrivOctets,
    parameters = Params,
    publicKey = MaybePub
}) ->
    case Params of
        {namedCurve, ?'secp256r1'} ->
            extract_validated_p256_key(PrivOctets, [MaybePub]);
        _ ->
            {error, <<"Unsupported EC curve; expected P-256 (secp256r1)">>}
    end;
decode_private_key_record(_) ->
    {error, <<"Unsupported private key algorithm; expected EC P-256">>}.

decode_ec_alg_params(asn1_NOVALUE) ->
    {ok, asn1_NOVALUE};
decode_ec_alg_params({namedCurve, ?'secp256r1'}) ->
    {ok, p256};
decode_ec_alg_params({asn1_OPENTYPE, CurveDer}) when is_binary(CurveDer) ->
    try public_key:der_decode('EcpkParameters', CurveDer) of
        {namedCurve, ?'secp256r1'} -> {ok, p256};
        _ -> error
    catch
        _:_ -> error
    end;
decode_ec_alg_params(_) ->
    error.

verify_combined_p256_curve(p256, asn1_NOVALUE) ->
    true;
verify_combined_p256_curve(p256, {namedCurve, ?'secp256r1'}) ->
    true;
verify_combined_p256_curve(asn1_NOVALUE, {namedCurve, ?'secp256r1'}) ->
    true;
verify_combined_p256_curve(_, _) ->
    false.

extract_validated_p256_key(PrivOctets, MaybePubs) ->
    PrivRaw = to_binary(PrivOctets),
    ByteLen = byte_size(PrivRaw),
    case ByteLen >= 1 andalso ByteLen =< 32 of
        false ->
            {error, <<"Invalid P-256 private scalar length">>};
        true ->
            PrivScalarBin = pad_scalar_32(PrivRaw),
            <<ScalarInt:256/big-unsigned-integer>> = PrivScalarBin,
            case ScalarInt >= 1 andalso ScalarInt < ?P256_N of
                false ->
                    {error, <<"P-256 private scalar out of range">>};
                true ->
                    try crypto:generate_key(ecdh, secp256r1, PrivScalarBin) of
                        {<<4, X:32/binary, Y:32/binary>> = ExpectedPub, _} ->
                            case
                                is_valid_p256_point(X, Y)
                                andalso verify_all_optional_pubs(MaybePubs, ExpectedPub)
                            of
                                true ->
                                    {ok, {PrivScalarBin, X, Y}};
                                false ->
                                    {error,
                                        <<"EC private key public point does not match private scalar">>}
                            end;
                        _ ->
                            {error, <<"Failed to derive uncompressed P-256 public point">>}
                    catch
                        _:_ ->
                            {error, <<"Failed to derive P-256 public key">>}
                    end
            end
    end.

verify_all_optional_pubs([], _ExpectedPub) ->
    true;
verify_all_optional_pubs([MaybePub | Rest], ExpectedPub) ->
    case verify_optional_pub(MaybePub, ExpectedPub) of
        true -> verify_all_optional_pubs(Rest, ExpectedPub);
        false -> false
    end.

verify_optional_pub(asn1_NOVALUE, _ExpectedPub) ->
    true;
verify_optional_pub(PubBin, ExpectedPub) when is_binary(PubBin) ->
    PubBin =:= ExpectedPub;
verify_optional_pub({0, PubBin}, ExpectedPub) when is_binary(PubBin) ->
    PubBin =:= ExpectedPub;
verify_optional_pub(_, _ExpectedPub) ->
    false.

decode_verify_entries([], AccRev) ->
    {ok, lists:reverse(AccRev)};
decode_verify_entries([Entry | Rest], AccRev) ->
    case decode_verify_entry(Entry) of
        {ok, XY} ->
            decode_verify_entries(Rest, [XY | AccRev]);
        {error, Reason} ->
            {error, Reason}
    end.

decode_verify_entry({'EncryptedPrivateKeyInfo', _Der, _Cipher}) ->
    {error, <<"Encrypted PEM keys are not supported">>};
decode_verify_entry({_Type, _Der, CipherInfo}) when CipherInfo =/= not_encrypted ->
    {error, <<"Encrypted PEM keys are not supported">>};
decode_verify_entry({'SubjectPublicKeyInfo', Der, not_encrypted} = Entry)
    when is_binary(Der), byte_size(Der) > 0
->
    try public_key:pem_entry_decode(Entry) of
        {#'ECPoint'{point = <<4, X:32/binary, Y:32/binary>>}, {namedCurve, ?'secp256r1'}} ->
            case is_valid_p256_point(X, Y) of
                true -> {ok, {X, Y}};
                false -> {error, <<"Public key point is not on P-256 curve">>}
            end;
        {#'ECPoint'{}, {namedCurve, ?'secp256r1'}} ->
            {error, <<"Expected uncompressed 65-byte P-256 public point">>};
        {#'ECPoint'{}, _} ->
            {error, <<"Unsupported EC curve; expected P-256 (secp256r1)">>};
        _ ->
            {error, <<"Unsupported public key algorithm; expected EC P-256">>}
    catch
        _:_ ->
            {error, <<"Malformed SubjectPublicKeyInfo PEM entry">>}
    end;
decode_verify_entry({Type, _Der, not_encrypted} = Entry)
    when Type =:= 'ECPrivateKey' orelse Type =:= 'PrivateKeyInfo'
->
    case decode_signing_entry(Entry) of
        {ok, {_PrivScalarBin, X, Y}} -> {ok, {X, Y}};
        {error, Reason} -> {error, Reason}
    end;
decode_verify_entry({_Type, <<>>, not_encrypted}) ->
    {error, <<"Empty PEM key payload">>};
decode_verify_entry({_Type, _Der, not_encrypted}) ->
    {error, <<"Unsupported PEM entry in verification keys">>}.

is_valid_p256_point(XBin, YBin)
    when is_binary(XBin),
         byte_size(XBin) =:= 32,
         is_binary(YBin),
         byte_size(YBin) =:= 32
->
    <<X:256/big-unsigned-integer>> = XBin,
    <<Y:256/big-unsigned-integer>> = YBin,
    case
        not (X =:= 0 andalso Y =:= 0)
        andalso X >= 0
        andalso X < ?P256_P
        andalso Y >= 0
        andalso Y < ?P256_P
    of
        false ->
            false;
        true ->
            Lhs = (Y * Y) rem ?P256_P,
            Rhs = mod_p(X * X * X - 3 * X + ?P256_B),
            Lhs =:= Rhs
    end;
is_valid_p256_point(_, _) ->
    false.

mod_p(Val) ->
    ((Val rem ?P256_P) + ?P256_P) rem ?P256_P.

pad_scalar_32(Bin) when byte_size(Bin) =:= 32 ->
    Bin;
pad_scalar_32(Bin) when byte_size(Bin) < 32 ->
    Pad = binary:copy(<<0>>, 32 - byte_size(Bin)),
    <<Pad/binary, Bin/binary>>.

to_binary(Bin) when is_binary(Bin) ->
    Bin;
to_binary(List) when is_list(List) ->
    list_to_binary(List).
