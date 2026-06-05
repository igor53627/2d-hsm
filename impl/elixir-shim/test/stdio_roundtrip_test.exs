defmodule EnclaveProtocol.StdioRoundtripTest do
  use ExUnit.Case, async: false

  @bridge_rel "../../rust/enclave-protocol/target/debug/enclave-stdio-bridge"

  defp bridge_path do
    Path.expand(@bridge_rel, __DIR__)
  end

  defp ensure_bridge! do
    path = bridge_path()

    {output, status} =
      System.cmd(
        "cargo",
        ["build", "--bin", "enclave-stdio-bridge"],
        cd: Path.expand("../../rust/enclave-protocol", __DIR__),
        stderr_to_stdout: true
      )

    if status != 0 do
      flunk("failed to build enclave-stdio-bridge:\n#{output}")
    end

    path
  end

  test "GET_MEASUREMENT roundtrip via stdio bridge" do
    path = ensure_bridge!()

    assert {:ok, resp} = EnclaveProtocol.StdioClient.get_measurement(path)
    assert resp.version == 1
    assert resp.measurement == "enclave-measurement-placeholder"
    assert resp.attestation == "attestation-placeholder"
    assert resp.supported_ticket_types == [0, 1]
    assert resp.pq_signing_ready == false
    assert resp.pq_pubkey == ""
  end

  test "framing roundtrip without bridge" do
    frame = EnclaveProtocol.Framing.build_get_measurement_request()
    assert {:ok, {0x01, payload}} = EnclaveProtocol.Framing.decode_frame(frame)
    assert match?({:ok, %{1 => 1}, _}, CBOR.decode(payload)) or match?({:ok, %{1 => 1}}, CBOR.decode(payload))
  end
end