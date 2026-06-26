# Producer vsock smoke — Elixir edition (TASK-122 AC#3 staging evidence)
#
# Drives the 2d-hsm staging enclave through a vsock↔UDS relay (Python) using the
# REAL Chain.ProducerHsm.Wire codec (the 2D producer signer client's CBOR layer).
# This is the literal "block producer uses 2d-hsm" evidence.
#
# Setup on aya:
#   /opt/elixir-1.16/bin/elixirc wire.ex          # compile Wire module
#   enclave-vsock-staging &                        # staging enclave on CID=1:5000
#   python3 vsock_uds_relay.py /tmp/phsm.sock 1 5000 &  # vsock↔UDS relay
#   /opt/elixir-1.16/bin/elixir producer_vsock_smoke.exs

defmodule Smoke do
  alias Chain.ProducerHsm.Wire

  @proto_ver 1
  @uds_path System.get_env("PRODUCER_HSM_UDS", "/tmp/phsm.sock")

  # Connect via UDS to the vsock↔UDS relay
  def connect do
    opts = [:binary, active: false, packet: :raw]
    case :gen_tcp.connect({:local, String.to_charlist(@uds_path)}, 0, opts, 5000) do
      {:ok, s} -> s
      {:error, reason} -> raise "UDS connect to #{@uds_path} failed: #{inspect(reason)}"
    end
  end

  def send_frame(s, type_byte, payload) do
    total = 2 + byte_size(payload)
    frame = <<total::32-big, @proto_ver, type_byte, payload::binary>>
    :ok = :gen_tcp.send(s, frame)
    :ok = :inet.setopts(s, recbuf: 1_048_576)
  end

  def recv_frame(s) do
    {:ok, <<total::32-big>>} = :gen_tcp.recv(s, 4, 5000)
    {:ok, <<@proto_ver, type, payload::binary>>} = :gen_tcp.recv(s, total, 5000)
    {type, payload}
  end

  def round_trip(s, type_byte, payload) do
    send_frame(s, type_byte, payload)
    recv_frame(s)
  end

  def run do
    IO.puts("Producer Elixir smoke via UDS relay at #{@uds_path}")
    s = connect()
    IO.puts("Connected to enclave (through vsock↔UDS relay)")

    results = []

    # 1. GET_MEASUREMENT
    IO.puts("\n=== GET_MEASUREMENT (0x01) ===")
    {:ok, gm_payload} = Wire.encode_get_measurement_request(%{version: 1})
    {0x01, gm_resp} = round_trip(s, 0x01, gm_payload)
    {:ok, gm} = Wire.decode_get_measurement_response(gm_resp)
    IO.puts("  measurement: #{byte_size(gm.measurement)} bytes")
    IO.puts("  pq_pubkey: #{byte_size(gm.pq_pubkey)} bytes (expect 1952)")
    IO.puts("  pq_signing_ready: #{gm.pq_signing_ready}")
    IO.puts("  supported_ticket_types: #{inspect(gm.supported_ticket_types)}")
    results = [check("GET_MEASUREMENT: 1952-byte pubkey + signing ready",
                      byte_size(gm.pq_pubkey) == 1952 and gm.pq_signing_ready == true) | results]

    # 2. GET_STATUS
    IO.puts("\n=== GET_STATUS (0x30) ===")
    {:ok, gs_payload} = Wire.encode_get_status_request(%{version: 1})
    {0x30, gs_resp} = round_trip(s, 0x30, gs_payload)
    {:ok, gs} = Wire.decode_get_status_response(gs_resp)
    IO.puts("  armed: #{gs.armed}")
    results = [check("GET_STATUS: disarmed", gs.armed == false) | results]

    # 3. SIGN_AUTHORIZATION_TICKET (recovery — enclave rejects without arming)
    IO.puts("\n=== SIGN_AUTHORIZATION_TICKET (0x10) ===")
    ticket = %{
      ticket_type: 0,
      nonce: 1,
      context_hash: :binary.copy(<<0xAB>>, 32),
      activation_height: 1000,
      new_measurement: :binary.copy(<<0x55>>, 48),
      pq_pubkey: gm.pq_pubkey,
      fork_spec_hash: nil,
      new_header_version: nil
    }
    {:ok, sat_payload} = Wire.encode_sign_authorization_ticket_request(%{ticket: ticket})
    {0x10, sat_resp} = round_trip(s, 0x10, sat_payload)

    if Wire.wire_error?(sat_resp) do
      {:ok, code, reason} = Wire.decode_wire_error(sat_resp)
      IO.puts("  wire error (expected): code=#{code} reason=#{reason}")
      results = [check("SIGN_AUTH: wire-error code=2", code == 2) | results]
    else
      {:ok, sat} = Wire.decode_sign_authorization_ticket_response(sat_resp)
      IO.puts("  SUCCESS: signature=#{byte_size(sat.signature)} bytes!")
      results = [check("SIGN_AUTH: 3309-byte signature", byte_size(sat.signature) == 3309) | results]
    end

    # 4. ARM_FOR_PRODUCTION (bogus proof → refused)
    IO.puts("\n=== ARM_FOR_PRODUCTION (0x20) ===")
    req = %{
      authorized_state: %{
        pq_pubkey: gm.pq_pubkey,
        measurement: gm.measurement,
        activated_at_height: 99,
        source_ticket_hash: :binary.copy(<<0xCC>>, 32)
      },
      recent_chain_proof: %{
        finalized_height: 100,
        finalized_header_hash: :binary.copy(<<0xDD>>, 32),
        recovery_history_tail: [:binary.copy(<<0xEE>>, 32)],
        proof_data: <<0x01>>,
        signature_from_recent_producer: :binary.copy(<<0xAA>>, 64)
      }
    }
    {:ok, arm_payload} = Wire.encode_arm_for_production_request(req)
    {0x20, arm_resp} = round_trip(s, 0x20, arm_payload)
    {:ok, arm} = Wire.decode_arm_for_production_response(arm_resp)
    IO.puts("  status: #{arm.status}")
    IO.puts("  reason: #{inspect(arm.reason)}")
    results = [check("ARM: refused (bogus proof)", arm.status == :refused) | results]

    :gen_tcp.close(s)

    IO.puts("\n============================================================")
    passed = Enum.count(results, & &1)
    total = length(results)
    IO.puts("#{passed}/#{total} checks passed")
    IO.puts("Producer signer client (Chain.ProducerHsm.Wire) drove the real")
    IO.puts("2d-hsm staging enclave via AF_VSOCK — TASK-122 AC#3 staging evidence.")

    if passed < total, do: System.halt(1)
  end

  defp check(label, true) do
    IO.puts("  [PASS] #{label}")
    true
  end
  defp check(label, false) do
    IO.puts("  [FAIL] #{label}")
    false
  end
end

Smoke.run()
