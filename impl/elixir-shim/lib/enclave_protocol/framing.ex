defmodule EnclaveProtocol.Framing do
  @moduledoc """
  Length-prefixed vsock framing (vsock spec §7): `[u32 BE total_len][u8 version][u8 msg_type][payload]`.
  `total_len` is `2 + byte_size(payload)`.
  """

  @protocol_version 1
  @msg_get_measurement 0x01
  @msg_sign_authorization_ticket 0x10
  @msg_get_status 0x30

  @doc "Message type for GET_MEASUREMENT."
  def msg_get_measurement, do: @msg_get_measurement

  @doc "Message type for SIGN_AUTHORIZATION_TICKET."
  def msg_sign_authorization_ticket, do: @msg_sign_authorization_ticket

  @doc "Message type for GET_STATUS."
  def msg_get_status, do: @msg_get_status

  @doc false
  def protocol_version, do: @protocol_version

  @doc """
  Build a framed GET_MEASUREMENT request (integer-key CBOR payload `{1 => 1}`).
  """
  @spec build_get_measurement_request() :: binary()
  def build_get_measurement_request do
    payload = CBOR.encode(%{1 => @protocol_version})
    encode_frame(@msg_get_measurement, payload)
  end

  @doc """
  Encode `payload` with the standard header.
  """
  @spec encode_frame(non_neg_integer(), binary()) :: binary()
  def encode_frame(msg_type, payload) when is_integer(msg_type) and is_binary(payload) do
    total_len = 2 + byte_size(payload)
    <<total_len::unsigned-big-integer-size(32), @protocol_version, msg_type, payload::binary>>
  end

  @doc """
  Decode one frame. Returns `{msg_type, payload}`.
  """
  @spec decode_frame(binary()) :: {:ok, {non_neg_integer(), binary()}} | {:error, term()}
  def decode_frame(
        <<total_len::unsigned-big-integer-size(32), version, msg_type, payload::binary>>
      ) do
    if version != @protocol_version do
      {:error, {:invalid_version, version}}
    else
      expected_payload = total_len - 2

      if byte_size(payload) != expected_payload do
        {:error, {:length_mismatch, expected_payload, byte_size(payload)}}
      else
        {:ok, {msg_type, payload}}
      end
    end
  end

  def decode_frame(_), do: {:error, :frame_too_short}

  @doc """
  Parse GET_MEASUREMENT success response CBOR (integer keys 1–6).
  """
  @spec decode_get_measurement_response(binary()) :: {:ok, map()} | {:error, term()}
  def decode_get_measurement_response(payload) when is_binary(payload) do
    with {:ok, map} <- decode_exact_map(payload) do
      decode_measurement_map(map)
    end
  end

  @doc "Parse SIGN_AUTHORIZATION_TICKET success response (integer keys 1–3)."
  @spec decode_sign_authorization_ticket_response(binary()) :: {:ok, map()} | {:error, term()}
  def decode_sign_authorization_ticket_response(payload) when is_binary(payload) do
    with {:ok, map} <- decode_exact_map(payload),
         1 <- Map.get(map, 1),
         signature when is_binary(signature) <- cbor_bytes(Map.get(map, 2)),
         ticket_hash when is_binary(ticket_hash) and byte_size(ticket_hash) == 32 <-
           cbor_bytes(Map.get(map, 3)) do
      {:ok, %{version: 1, signature: signature, ticket_hash: ticket_hash}}
    else
      _ -> {:error, :invalid_sign_response}
    end
  end

  defp decode_measurement_map(map) do
    with 1 <- Map.get(map, 1),
             measurement when is_binary(measurement) <- cbor_bytes(Map.get(map, 2)),
             attestation when is_binary(attestation) <- cbor_bytes(Map.get(map, 3)),
             pq_pubkey when is_binary(pq_pubkey) <- cbor_bytes(Map.get(map, 4)),
             types when is_list(types) <- Map.get(map, 5),
             ready when is_boolean(ready) <- Map.get(map, 6) do
          {:ok,
           %{
             version: 1,
             measurement: measurement,
             attestation: attestation,
             pq_pubkey: pq_pubkey,
             supported_ticket_types: types,
             pq_signing_ready: ready
           }}
    else
      _ -> {:error, :invalid_get_measurement_response}
    end
  end

  @doc "Parse GET_STATUS response (integer keys 1–9)."
  @spec decode_get_status_response(binary()) :: {:ok, map()} | {:error, term()}
  def decode_get_status_response(payload) when is_binary(payload) do
    with {:ok, map} <- decode_exact_map(payload) do
      decode_status_map(map)
    end
  end

  defp decode_exact_map(payload) do
    case CBOR.decode(payload) do
      {:ok, map, rest} when is_map(map) and rest in ["", <<>>] ->
        {:ok, map}

      {:ok, _, _} ->
        {:error, :trailing_cbor_bytes}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp decode_status_map(map) do
    with 1 <- Map.get(map, 1),
         armed when is_boolean(armed) <- Map.get(map, 2) do
      {:ok,
       %{
         version: 1,
         armed: armed,
         authorized_measurement: cbor_bytes(Map.get(map, 3)),
         authorized_pq_pubkey: cbor_bytes(Map.get(map, 4)),
         authorized_activated_at_height: Map.get(map, 5),
         proof_finalized_height: Map.get(map, 6),
         source_ticket_hash: cbor_optional_bytes(Map.get(map, 7)),
         pending_hard_fork_height: Map.get(map, 8),
         last_known_block: Map.get(map, 9)
       }}
    else
      _ -> {:error, :invalid_get_status_response}
    end
  end

  defp cbor_optional_bytes(%CBOR.Tag{tag: :bytes, value: bin}) when is_binary(bin), do: bin
  defp cbor_optional_bytes(bin) when is_binary(bin), do: bin
  defp cbor_optional_bytes(nil), do: nil
  defp cbor_optional_bytes(_), do: nil

  defp cbor_bytes(%CBOR.Tag{tag: :bytes, value: bin}) when is_binary(bin), do: bin
  defp cbor_bytes(bin) when is_binary(bin), do: bin
  defp cbor_bytes(_), do: nil
end