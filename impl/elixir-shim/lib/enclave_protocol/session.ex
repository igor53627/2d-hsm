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

    with {:ok, response} <- Socket.request(socket, frame),
         {:ok, {msg, payload}} <- Framing.decode_frame(response),
         true <- msg == Framing.msg_get_measurement(),
         {:ok, body} <- Framing.decode_get_measurement_response(payload) do
      {:ok, body}
    else
      false -> {:error, :unexpected_message_type}
      {:error, _} = err -> err
    end
  end

  @doc "GET_STATUS"
  @spec get_status(t()) :: {:ok, map()} | {:error, term()}
  def get_status(%__MODULE__{socket: socket}) do
    payload = CBOR.encode(%{1 => 1})
    frame = Framing.encode_frame(Framing.msg_get_status(), payload)

    with {:ok, response} <- Socket.request(socket, frame),
         {:ok, {msg, body}} <- Framing.decode_frame(response),
         true <- msg == Framing.msg_get_status(),
         {:ok, status} <- Framing.decode_get_status_response(body) do
      {:ok, status}
    else
      false -> {:error, :unexpected_message_type}
      {:error, _} = err -> err
    end
  end

  @doc "Send a pre-built framed request (e.g. from `TestFixtures`) and return raw response frame."
  @spec request_raw(t(), binary()) :: {:ok, binary()} | {:error, term()}
  def request_raw(%__MODULE__{socket: socket}, frame) do
    Socket.request(socket, frame)
  end

  @doc """
  Send a framed SIGN_AUTHORIZATION_TICKET request and parse the success response.
  """
  @spec sign_authorization_ticket(t(), binary()) :: {:ok, map()} | {:error, term()}
  def sign_authorization_ticket(%__MODULE__{socket: socket}, request_frame) do
    with {:ok, response} <- Socket.request(socket, request_frame),
         {:ok, {msg, payload}} <- Framing.decode_frame(response),
         true <- msg == Framing.msg_sign_authorization_ticket(),
         {:ok, body} <- Framing.decode_sign_authorization_ticket_response(payload) do
      {:ok, body}
    else
      false -> {:error, :unexpected_message_type}
      {:error, _} = err -> err
    end
  end
end