defmodule EnclaveProtocol.FramingTest do
  use ExUnit.Case, async: true

  test "decode_get_status_response rejects map missing keys 5-9" do
    payload =
      CBOR.encode(%{
        1 => 1,
        2 => false,
        3 => %CBOR.Tag{tag: :bytes, value: <<>>},
        4 => %CBOR.Tag{tag: :bytes, value: <<>>}
      })

    assert {:error, :invalid_get_status_response} =
             EnclaveProtocol.Framing.decode_get_status_response(payload)
  end

  test "decode_get_status_response accepts explicit nulls for nullable fields" do
    payload =
      CBOR.encode(%{
        1 => 1,
        2 => false,
        3 => %CBOR.Tag{tag: :bytes, value: <<>>},
        4 => %CBOR.Tag{tag: :bytes, value: <<>>},
        5 => nil,
        6 => nil,
        7 => nil,
        8 => nil,
        9 => nil
      })

    assert {:ok, status} = EnclaveProtocol.Framing.decode_get_status_response(payload)
    refute status.armed
    assert status.proof_finalized_height == nil
  end
end