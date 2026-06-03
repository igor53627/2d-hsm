defmodule EnclaveProtocol.Session do
  @moduledoc """
  Stateful host client over UDS (reference TASK-2 Phase 4 transport).
  """

  alias EnclaveProtocol.{Framing, Socket}

  defstruct [:socket, :path]

  @type t :: %__MODULE__{socket: port(), path: String.t()}

  @doc "Open a session to `path` (Unix socket from `enclave-uds-server`)."
  @spec connect(Path.t()) :: {:ok, t()} | {:error, term()}
  def connect(path) do
    case Socket.connect(path) do
      {:ok, socket} -> {:ok, %__MODULE__{socket: socket, path: path}}
      {:error, _} = err -> err
    end
  end

  @doc "Close the session socket."
  @spec close(t()) :: :ok
  def close(%__MODULE__{socket: socket}) do
    Socket.close(socket)
  end

  @doc "GET_MEASUREMENT"
  @spec get_measurement(t()) :: {:ok, map()} | {:error, term()}
  def get_measurement(%__MODULE__{socket: socket}) do
    frame = Framing.build_get_measurement_request()
    request_and_decode(socket, Framing.msg_get_measurement(), frame)
  end

  @doc "GET_STATUS"
  @spec get_status(t()) :: {:ok, map()} | {:error, term()}
  def get_status(%__MODULE__{socket: socket}) do
    payload = CBOR.encode(%{1 => 1})
    frame = Framing.encode_frame(Framing.msg_get_status(), payload)
    request_and_decode(socket, Framing.msg_get_status(), frame)
  end

  @doc "ARM_FOR_PRODUCTION (pass a pre-built request frame from `TestFixtures`)."
  @spec arm_for_production(t(), binary()) :: {:ok, map()} | {:error, term()}
  def arm_for_production(%__MODULE__{socket: socket}, request_frame) do
    request_and_decode(socket, Framing.msg_arm_for_production(), request_frame)
  end

  @doc "SIGN_AUTHORIZATION_TICKET (pass a pre-built request frame from `TestFixtures`)."
  @spec sign_authorization_ticket(t(), binary()) :: {:ok, map()} | {:error, term()}
  def sign_authorization_ticket(%__MODULE__{socket: socket}, request_frame) do
    request_and_decode(socket, Framing.msg_sign_authorization_ticket(), request_frame)
  end

  defp request_and_decode(socket, expected_msg, request_frame) do
    with {:ok, response} <- Socket.request(socket, request_frame),
         {:ok, {msg, payload}} <- Framing.decode_frame(response),
         true <- msg == expected_msg,
         {:ok, body} <- Framing.decode_response_payload(msg, payload) do
      {:ok, body}
    else
      false -> {:error, :unexpected_message_type}
      {:error, _} = err -> err
    end
  end
end