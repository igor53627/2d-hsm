defmodule EnclaveProtocol.Socket do
  @moduledoc """
  Unix domain socket transport (dev stand-in for vsock; same framing as production).
  """

  alias EnclaveProtocol.Framing

  @read_timeout_ms 5_000

  @doc "Connect to the reference enclave UDS server."
  @spec connect(Path.t()) :: {:ok, port()} | {:error, term()}
  def connect(path) when is_binary(path) do
    :gen_tcp.connect({:local, String.to_charlist(path)}, 0, [
      :binary,
      {:active, false}
    ])
  end

  @doc "Send a framed message and read the framed response."
  @spec request(port(), binary()) :: {:ok, binary()} | {:error, term()}
  def request(socket, frame) when is_port(socket) and is_binary(frame) do
    with :ok <- :gen_tcp.send(socket, frame),
         {:ok, <<len::unsigned-big-integer-size(32)>>} <- read_exact(socket, 4),
         true <- len > 0 and len <= Framing.max_payload_len(),
         {:ok, body} <- read_exact(socket, len) do
      {:ok, <<len::unsigned-big-integer-size(32), body::binary>>}
    else
      false ->
        close(socket)
        {:error, :frame_too_large}

      {:error, _} = err ->
        close(socket)
        err
    end
  end

  @doc "Close the socket."
  @spec close(port()) :: :ok
  def close(socket) when is_port(socket) do
    :gen_tcp.close(socket)
  end

  defp read_exact(_socket, 0), do: {:ok, <<>>}

  defp read_exact(socket, nbytes) when nbytes > 0 do
    case :gen_tcp.recv(socket, nbytes, @read_timeout_ms) do
      {:ok, data} when byte_size(data) == nbytes ->
        {:ok, data}

      {:ok, data} ->
        case read_exact(socket, nbytes - byte_size(data)) do
          {:ok, rest} -> {:ok, data <> rest}
          {:error, _} = err -> err
        end

      {:error, _} = err ->
        err
    end
  end
end