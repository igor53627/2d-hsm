defmodule EnclaveProtocol.StdioClient do
  @moduledoc """
  Host-side client for the reference enclave via `enclave-stdio-bridge` (one request per process).

  Production will use vsock; this module is for local integration tests and Elixir shim development.
  """

  alias EnclaveProtocol.Framing

  @read_timeout_ms 5_000

  @doc """
  Send GET_MEASUREMENT to `bridge_path` and return the decoded response map.

  `bridge_path` must point to `cargo build --bin enclave-stdio-bridge` output.
  """
  @spec get_measurement(Path.t()) :: {:ok, map()} | {:error, term()}
  def get_measurement(bridge_path) do
    if File.regular?(bridge_path) do
      request = Framing.build_get_measurement_request()

      msg_type = Framing.msg_get_measurement()

      with {:ok, response} <- run_bridge(bridge_path, request),
           {:ok, {^msg_type, payload}} <- Framing.decode_frame(response),
           {:ok, body} <- Framing.decode_get_measurement_response(payload) do
        {:ok, body}
      else
        {:ok, {other, _}} -> {:error, {:unexpected_message_type, other}}
        {:error, _} = err -> err
      end
    else
      {:error, {:bridge_not_found, bridge_path}}
    end
  end

  defp run_bridge(executable, request) do
    port =
      Port.open({:spawn_executable, executable}, [
        :binary,
        :exit_status,
        {:args, []}
      ])

    Port.command(port, request)

    collect_output(port, [], @read_timeout_ms)
  end

  defp safe_port_close(port) do
    case Port.info(port) do
      nil -> :ok
      _ -> Port.close(port)
    end
  rescue
    ArgumentError -> :ok
  end

  defp collect_output(port, acc, timeout) do
    receive do
      {^port, {:data, data}} ->
        collect_output(port, [acc, data], timeout)

      {^port, {:exit_status, 0}} ->
        safe_port_close(port)
        {:ok, IO.iodata_to_binary(acc)}

      {^port, {:exit_status, code}} ->
        safe_port_close(port)
        {:error, {:bridge_exit, code, IO.iodata_to_binary(acc)}}
    after
      timeout ->
        safe_port_close(port)
        {:error, :bridge_timeout}
    end
  end
end