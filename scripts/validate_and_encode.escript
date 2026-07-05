#!/usr/bin/env escript
%% -*- erlang -*-

main([MainSchema, TopType, JsonFile, OutputDerFile]) ->
    code:add_patha("."), %% Add current directory to code path so modules find each other

    %% 1. Find all ASN.1 files in the current workspace directory to handle imports
    AsnFiles = filelib:wildcard("*.asn") ++ filelib:wildcard("*.asn1"),
    io:format("Found ASN.1 files in workspace: ~p~n", [AsnFiles]),

    %% 2. Compile ALL discovered schemas so their runtime bytecode (.beam) is generated
    CompileResults = [ {F, asn1ct:compile(F, [maps, der, {outdir, "."}])} || F <- AsnFiles ],

    %% 3. Check if our targeted main schema compiled successfully
    case lists:keyfind(MainSchema, 1, CompileResults) of
        {MainSchema, ok} ->
            ModuleName = filename:rootname(filename:basename(MainSchema)),
            Module = list_to_atom(ModuleName),

            io:format("Reading JSON input: ~s...~n", [JsonFile]),
            case file:read_file(JsonFile) of
                {ok, JsonBin} ->
                    try
                        RawMap = json:decode(JsonBin),
                        ErlangTerm = normalize_json(RawMap),

                        io:format("Encoding to DER for Top-Level Type: ~s...~n", [TopType]),
                        TypeAtom = list_to_atom(TopType),

                        case Module:encode(TypeAtom, ErlangTerm) of
                            {ok, DerBinary} ->
                                case file:write_file(OutputDerFile, DerBinary) of
                                    ok ->
                                        io:format("Success! DER generated and saved to: ~s~n", [OutputDerFile]),
                                        init:stop(0);
                                    {error, WriteErr} ->
                                        io:format("Error writing output file: ~p~n", [WriteErr]),
                                        init:stop(1)
                                end;
                            {error, EncodeErr} ->
                                io:format("ASN.1 Encoding Failure: ~p~n", [EncodeErr]),
                                init:stop(1)
                        end
                    catch
                        E:R:S ->
                            io:format("Error processing JSON structure: ~p:~p~n~p~n", [E, R, S]),
                            init:stop(1)
                    end;
                {error, ReadErr} ->
                    io:format("Error reading JSON file: ~p~n", [ReadErr]),
                    init:stop(1)
            end;
        _ ->
            io:format("Error: Main schema ~s failed to compile or was not found in workspace.~n", [MainSchema]),
            init:stop(1)
    end;
main(_) ->
    io:format("Usage: validate_and_encode <main_schema.asn> <TopLevelType> <input.json> <output.der>~n"),
    init:stop(1).

%% Helper to recursively convert JSON keys to atoms (required for ASN.1 fields)
normalize_json(Map) when is_map(Map) ->
    maps:from_list([{binary_to_atom(K, utf8), normalize_json(V)} || {K, V} <- maps:to_list(Map)]);
normalize_json(List) when is_list(List) ->
    [normalize_json(X) || X <- List];
normalize_json(Binary) when is_binary(Binary) ->
    case Binary of
        <<"__atom__:", Rest/binary>> -> binary_to_atom(Rest, utf8);
        _ -> Binary
    end;
normalize_json(Val) ->
    Val.
