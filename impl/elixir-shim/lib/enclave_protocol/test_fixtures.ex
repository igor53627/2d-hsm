defmodule EnclaveProtocol.TestFixtures do
  @moduledoc """
  Export wire frames from the Rust reference (`enclave-stdio-session` subcommands).
  """

  @doc "Hex-decoded framed `ARM_FOR_PRODUCTION` request from reference test vectors."
  @spec arm_frame(Path.t()) :: {:ok, binary()} | {:error, term()}
  def arm_frame(session_bin) do
    export_hex_frame(session_bin, "export-arm-frame")
  end

  @doc "Hex-decoded framed recovery `SIGN_AUTHORIZATION_TICKET` request."
  @spec recovery_sign_frame(Path.t()) :: {:ok, binary()} | {:error, term()}
  def recovery_sign_frame(session_bin) do
    export_hex_frame(session_bin, "export-recovery-sign-frame")
  end

  @doc "Hex-decoded framed hard-fork `SIGN_AUTHORIZATION_TICKET` (first fork in armed session)."
  @spec hardfork_sign_frame(Path.t()) :: {:ok, binary()} | {:error, term()}
  def hardfork_sign_frame(session_bin) do
    export_hex_frame(session_bin, "export-hardfork-sign-frame")
  end

  @doc "Hex-decoded second hard-fork sign frame (must be rejected while still armed)."
  @spec second_hardfork_sign_frame(Path.t()) :: {:ok, binary()} | {:error, term()}
  def second_hardfork_sign_frame(session_bin) do
    export_hex_frame(session_bin, "export-second-hardfork-sign-frame")
  end

  defp export_hex_frame(bin, arg) do
    case System.cmd(bin, [arg], stderr_to_stdout: true) do
      {hex, 0} ->
        case Base.decode16(String.trim(hex), case: :mixed) do
          {:ok, frame} -> {:ok, frame}
          :error -> {:error, {:invalid_fixture_hex, String.trim(hex)}}
        end

      {output, code} ->
        {:error, {:export_failed, code, output}}
    end
  end
end