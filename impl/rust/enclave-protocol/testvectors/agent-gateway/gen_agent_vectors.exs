# TASK-7.1 golden-vector generator — run from the sibling ../2d checkout:
#   cd ../2d && mix run --no-start \
#     <2d-hsm>/impl/rust/enclave-protocol/testvectors/agent-gateway/gen_agent_vectors.exs
#   (writes vectors next to this script via __DIR__; same in-repo path as this dir's README)
# Produces frozen Agent Gateway test vectors from 2D's OWN crypto (authoritative
# against the live verifier) and self-checks each via signature recovery.

alias Chain.Crypto
alias Chain.Crypto.Address
alias Chain.Tron

# Write next to this script (the testvectors/agent-gateway/ dir), so any contributor
# can regenerate regardless of checkout location or cwd.
out = __DIR__
File.mkdir_p!(out)

# secp256k1 group order n and n/2 for low-S assertion
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
half_n = div(n, 2)

chain_id = 11_565
gas_price = 1_000_000_000
gas_limit = 21_000

enc_int = fn
  0 -> <<>>
  x when is_integer(x) and x > 0 -> :binary.encode_unsigned(x)
end

hex = fn b -> "0x" <> Base.encode16(b, case: :lower) end

# Deterministic TEST-ONLY keys (well-known Anvil dev keys; never production).
sk_transfer = Base.decode16!("AC0974BEC39A17E36BA4A6B4D238FF944BACB478CBED5EFCAE784D7BF4F2FF80")
sk_treasury = Base.decode16!("59C6995E998F97A5A0044966F0945389DC9E86DAE88C7A8412F4603B6B78690D")

identity = fn label, sk ->
  {:ok, pub} = ExSecp256k1.create_public_key(sk)
  <<0x04, _::binary-64>> = pub
  {:ok, addr} = Address.from_uncompressed_pubkey(pub)
  %{
    label: label,
    privkey: hex.(sk),
    pubkey_uncompressed_sec1: hex.(pub),
    eth_address: hex.(addr),
    tron_address: Tron.Address.encode(addr),
    address_body_20: hex.(addr)
  }
end

transfer = identity.("agent_transfer_k1#0", sk_transfer)
treasury = identity.("agent_faucet_treasury_k1", sk_treasury)

{:ok, pub_transfer} = ExSecp256k1.create_public_key(sk_transfer)
{:ok, addr_transfer} = Address.from_uncompressed_pubkey(pub_transfer)
{:ok, addr_treasury} = Address.from_uncompressed_pubkey(sk_treasury |> ExSecp256k1.create_public_key() |> elem(1))

low_s? = fn s_bin -> :binary.decode_unsigned(s_bin) <= half_n end

# ---------------------------------------------------------------------------
# Vector 1: eth EIP-155 ordinary transfer (from transfer key -> treasury addr)
# ---------------------------------------------------------------------------
nonce = 0
value = 1_000_000_000_000_000_000
to = addr_treasury
data = <<>>

unsigned_rlp =
  ExRLP.encode([
    enc_int.(nonce),
    enc_int.(gas_price),
    enc_int.(gas_limit),
    to,
    enc_int.(value),
    data,
    enc_int.(chain_id),
    <<>>,
    <<>>
  ])

signing_hash = Crypto.keccak256(unsigned_rlp)
{:ok, {sig64, recovery_id}} = ExSecp256k1.sign_compact(signing_hash, sk_transfer)
<<r_bin::binary-32, s_bin::binary-32>> = sig64
true = low_s?.(s_bin)
v = chain_id * 2 + 35 + recovery_id

signed_rlp =
  ExRLP.encode([
    enc_int.(nonce),
    enc_int.(gas_price),
    enc_int.(gas_limit),
    to,
    enc_int.(value),
    data,
    enc_int.(v),
    r_bin |> :binary.decode_unsigned() |> enc_int.(),
    s_bin |> :binary.decode_unsigned() |> enc_int.()
  ])

# self-check: recover signer == transfer address
{:ok, rec_pub} = ExSecp256k1.recover(signing_hash, r_bin, s_bin, recovery_id)
{:ok, rec_addr} = Address.from_uncompressed_pubkey(rec_pub)
^addr_transfer = rec_addr

File.write!("#{out}/ordinary_tx_v1.preimage.bin", unsigned_rlp)
File.write!("#{out}/ordinary_tx_v1.signing_hash.bin", signing_hash)
File.write!("#{out}/ordinary_tx_v1.signed.bin", signed_rlp)

eth_json = %{
  "_comment" => "Frozen 2D ordinary (eth EIP-155) transfer golden vector. TASK-7.1 AC#13. Generated from 2D Chain.Crypto.Envelope encoding. TEST KEYS ONLY.",
  "surface" => "eth_eip155_rlp",
  "chain_id" => chain_id,
  "hash_algorithm" => "keccak256",
  "fields" => %{
    "from" => transfer.eth_address,
    "to" => hex.(to),
    "nonce" => nonce,
    "gas_price" => gas_price,
    "gas_limit" => gas_limit,
    "value" => value,
    "data" => "0x"
  },
  "unsigned_rlp_preimage" => hex.(unsigned_rlp),
  "signing_hash_keccak256" => hex.(signing_hash),
  "signature" => %{"r" => hex.(r_bin), "s" => hex.(s_bin), "recovery_id" => recovery_id, "v_eip155" => v, "low_s" => true},
  "signed_rlp" => hex.(signed_rlp),
  "recovered_from" => hex.(rec_addr)
}

# ---------------------------------------------------------------------------
# Vector 2: TRON protobuf TransferContract (RESERVED surface; for AC#15 domain
# separation proof + future TASK-7.x). owner=transfer, to=treasury.
# Fixed (deterministic) ref-block / timing so the vector is frozen.
# ---------------------------------------------------------------------------
owner21 = <<0x41>> <> addr_transfer
to21 = <<0x41>> <> addr_treasury
amount = 1_000_000_000_000_000_000
expiration = 1_900_000_030_000
timestamp = 1_900_000_000_000

contract_bytes = Tron.Protobuf.encode_contract(:transfer, %{owner: owner21, to: to21, amount: amount})

raw_data =
  Tron.Protobuf.encode_raw_data(%{
    ref_block_bytes: <<0, 0>>,
    ref_block_hash: <<0::64>>,
    expiration: expiration,
    contracts: [contract_bytes],
    timestamp: timestamp
  })

tx_id = Crypto.sha256(raw_data)
{:ok, {tron_sig64, tron_rid}} = ExSecp256k1.sign_compact(tx_id, sk_transfer)
<<tr_r::binary-32, tr_s::binary-32>> = tron_sig64
true = low_s?.(tr_s)
tron_sig65 = tron_sig64 <> <<tron_rid>>

# self-check via 2D's own tron sender recovery
{:ok, tron_rec_addr} = Crypto.recover_tron_sender(raw_data, tron_sig65)
^addr_transfer = tron_rec_addr

File.write!("#{out}/tron_transfer_v1.raw_data.bin", raw_data)
File.write!("#{out}/tron_transfer_v1.txid.bin", tx_id)

tron_json = %{
  "_comment" => "RESERVED TRON-surface vector (eth-MVP + reserve-TRON decision). For AC#15 3-way domain-separation proof and future TASK-7.x. TEST KEYS ONLY.",
  "surface" => "tron_protobuf",
  "hash_algorithm" => "sha256",
  "raw_data_first_byte" => hex.(binary_part(raw_data, 0, 1)),
  "fields" => %{
    "owner_address_41" => hex.(owner21),
    "to_address_41" => hex.(to21),
    "amount" => amount,
    "ref_block_bytes" => "0x0000",
    "ref_block_hash" => "0x0000000000000000",
    "expiration" => expiration,
    "timestamp" => timestamp
  },
  "raw_data_preimage" => hex.(raw_data),
  "txid_sha256" => hex.(tx_id),
  "signature_65_rsv" => hex.(tron_sig65),
  "recovered_from" => hex.(tron_rec_addr)
}

# ---------------------------------------------------------------------------
# Vector 3: EIP-191-style identity-proof preimage (TASK-7.1 owns layout;
# TASK-7.3 owns the final non-collision proof). Disjoint from BOTH tx surfaces.
#   0x19 || len(label)(1B) || label || chain_id(8B BE) || len(env_id)(1B) || env_id
#        || key_ref(32B) || pubkey(65B uncompressed) || address(20B) || verifier_nonce(32B)
# Every variable-length field is 1-byte length-prefixed so a future label/env-id
# change cannot shift the parse of later fixed-width fields.
# ---------------------------------------------------------------------------
label = "2d-hsm/agent-identity-proof/v1"
env_id = "testnet"
key_ref = Crypto.keccak256("agent_transfer_k1#0")
verifier_nonce = :binary.copy(<<0xAB>>, 32)

id_preimage =
  <<0x19>> <>
    <<byte_size(label)::unsigned-8>> <> label <>
    <<chain_id::unsigned-big-64>> <>
    <<byte_size(env_id)::unsigned-8>> <> env_id <>
    key_ref <>
    pub_transfer <>
    addr_transfer <>
    verifier_nonce

id_hash = Crypto.keccak256(id_preimage)
{:ok, {id_sig64, id_rid}} = ExSecp256k1.sign_compact(id_hash, sk_transfer)
<<id_r::binary-32, id_s::binary-32>> = id_sig64
true = low_s?.(id_s)

File.write!("#{out}/identity_proof_v1.preimage.bin", id_preimage)
File.write!("#{out}/identity_proof_v1.signing_hash.bin", id_hash)

id_json = %{
  "_comment" => "EIP-191-style Agent Gateway identity-proof preimage. TASK-7.1 AC#15 (layout); TASK-7.3 owns final non-collision proof. TEST KEYS ONLY.",
  "domain_prefix_byte" => "0x19",
  "label" => label,
  "hash_algorithm" => "keccak256",
  "layout" => "0x19 || len(label)(1B) || label || chain_id(8B BE) || len(env_id)(1B) || env_id || key_ref(32B) || pubkey(65B) || address(20B) || verifier_nonce(32B)",
  "fields" => %{
    "chain_id" => chain_id,
    "environment_identifier" => env_id,
    "key_ref" => hex.(key_ref),
    "pubkey_uncompressed" => hex.(pub_transfer),
    "address" => hex.(addr_transfer),
    "verifier_nonce" => hex.(verifier_nonce)
  },
  "preimage" => hex.(id_preimage),
  "signing_hash_keccak256" => hex.(id_hash),
  "signature" => %{"r" => hex.(id_r), "s" => hex.(id_s), "recovery_id" => id_rid, "low_s" => true}
}

# ---------------------------------------------------------------------------
# Disjointness witnesses (AC#15): first byte of each preimage
# ---------------------------------------------------------------------------
disjoint = %{
  "_comment" => "3-way domain separation witnesses. eth RLP list first byte >= 0xc0; TRON protobuf first byte is a protobuf field tag; identity proof first byte 0x19. Hash algs also differ (eth/identity keccak256, tron sha256).",
  "eth_preimage_first_byte" => hex.(binary_part(unsigned_rlp, 0, 1)),
  "tron_preimage_first_byte" => hex.(binary_part(raw_data, 0, 1)),
  "identity_preimage_first_byte" => hex.(binary_part(id_preimage, 0, 1)),
  "eth_hash_alg" => "keccak256",
  "tron_hash_alg" => "sha256",
  "identity_hash_alg" => "keccak256",
  "note_eip2718" => "0x19 is a legal EIP-2718 TransactionType; 2D must permanently reserve/never assign type 0x19 (TASK-132.5 family). Enclave cannot enforce a 2D type assignment."
}

keys_json = %{
  "_comment" => "TEST-ONLY secp256k1 keypairs (well-known Anvil dev keys). NEVER production. Demonstrates dual eth/TRON address encodings of one unified account.",
  "transfer_key" => transfer,
  "treasury_key" => treasury
}

File.write!("#{out}/keys.json", Jason.encode!(keys_json, pretty: true))
File.write!("#{out}/ordinary_tx_v1.json", Jason.encode!(eth_json, pretty: true))
File.write!("#{out}/tron_transfer_v1.json", Jason.encode!(tron_json, pretty: true))
File.write!("#{out}/identity_proof_v1.json", Jason.encode!(id_json, pretty: true))
File.write!("#{out}/domain_separation.json", Jason.encode!(disjoint, pretty: true))

IO.puts("OK — vectors written to #{out}")
IO.puts("transfer eth=#{transfer.eth_address} tron=#{transfer.tron_address}")
IO.puts("treasury eth=#{treasury.eth_address} tron=#{treasury.tron_address}")
IO.puts("eth   first_byte=#{disjoint["eth_preimage_first_byte"]} hash=#{eth_json["signing_hash_keccak256"]}")
IO.puts("tron  first_byte=#{disjoint["tron_preimage_first_byte"]} txid=#{tron_json["txid_sha256"]}")
IO.puts("ident first_byte=#{disjoint["identity_preimage_first_byte"]} hash=#{id_json["signing_hash_keccak256"]}")
IO.puts("eth recover OK / tron recover OK / low-S all true")
