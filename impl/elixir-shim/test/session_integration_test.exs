defmodule EnclaveProtocol.SessionIntegrationTest do
  use ExUnit.Case, async: false

  @uds_rel "../../rust/enclave-protocol/target/debug/enclave-uds-server"
  @session_rel "../../rust/enclave-protocol/target/debug/enclave-stdio-session"

  setup_all do
    build_reference_bins!()
    socket_path = unique_socket_path()
    start_uds_server!(socket_path)
    on_exit(fn -> stop_uds_server(socket_path) end)
    {:ok, socket_path: socket_path}
  end

  test "GET_MEASUREMENT and GET_STATUS over UDS session", %{socket_path: socket_path} do
    assert {:ok, session} = EnclaveProtocol.Session.connect(socket_path)
    on_exit(fn -> EnclaveProtocol.Session.close(session) end)

    assert {:ok, meas} = EnclaveProtocol.Session.get_measurement(session)
    assert meas.supported_ticket_types == [0, 1]
    refute meas.pq_signing_ready

    assert {:ok, status} = EnclaveProtocol.Session.get_status(session)
    refute status.armed
  end

  test "recovery SIGN_AUTHORIZATION_TICKET over UDS", %{socket_path: socket_path} do
    session_bin = Path.expand(@session_rel, __DIR__)

    assert {:ok, session} = EnclaveProtocol.Session.connect(socket_path)
    on_exit(fn -> EnclaveProtocol.Session.close(session) end)

    assert {:ok, sign_frame} = EnclaveProtocol.TestFixtures.recovery_sign_frame(session_bin)

    assert {:ok, sign} = EnclaveProtocol.Session.sign_authorization_ticket(session, sign_frame)
    assert byte_size(sign.signature) == 64
    assert byte_size(sign.ticket_hash) == 32
  end

  test "ARM → GET_STATUS armed over UDS", %{socket_path: socket_path} do
    session_bin = Path.expand(@session_rel, __DIR__)

    assert {:ok, session} = EnclaveProtocol.Session.connect(socket_path)
    on_exit(fn -> EnclaveProtocol.Session.close(session) end)

    assert {:ok, arm_frame} = EnclaveProtocol.TestFixtures.arm_frame(session_bin)
    assert {:ok, %{status: "armed"}} = EnclaveProtocol.Session.arm_for_production(session, arm_frame)

    assert {:ok, status} = EnclaveProtocol.Session.get_status(session)
    assert status.armed
    assert status.proof_finalized_height == 10_000_050
  end

  defp unique_socket_path do
    id = :erlang.unique_integer([:positive, :monotonic])
    Path.join(System.user_home!(), ".2d-hsm/enclave-test-#{id}.sock")
  end

  defp build_reference_bins! do
    base = Path.expand("../../rust/enclave-protocol", __DIR__)

    case System.cmd(
           "cargo",
           [
             "build",
             "--bin",
             "enclave-uds-server",
             "--bin",
             "enclave-stdio-session",
             "--features",
             "test-support,demo-mock-sign"
           ],
           cd: base,
           stderr_to_stdout: true
         ) do
      {_, 0} -> :ok
      {out, code} -> flunk("cargo build failed (#{code}):\n#{out}")
    end
  end

  defp start_uds_server!(socket_path) do
    stop_uds_server(socket_path)
    File.mkdir_p!(Path.dirname(socket_path))
    uds = Path.expand(@uds_rel, __DIR__)

    port =
      Port.open({:spawn_executable, uds}, [
        :binary,
        :exit_status,
        {:args, []},
        {:env, [{~c"2D_HSM_ENCLAVE_SOCKET", to_charlist(socket_path)}]}
      ])

    Process.put(:enclave_uds_port, port)
    wait_for_socket(socket_path, 50)
  end

  defp stop_uds_server(socket_path) do
    if port = Process.get(:enclave_uds_port) do
      Port.close(port)
    end

    File.rm(socket_path)
  end

  defp wait_for_socket(path, 0), do: flunk("UDS server did not create #{path}")

  defp wait_for_socket(path, n) do
    if File.exists?(path), do: :ok, else: (Process.sleep(100); wait_for_socket(path, n - 1))
  end
end