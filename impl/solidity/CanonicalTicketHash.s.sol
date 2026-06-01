// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Script} from "forge-std/Script.sol";
import {stdJson} from "forge-std/StdJson.sol";

/// @title CanonicalTicketHash
/// @notice Computes the exact `keccak256(abi.encode(...))` used for AuthorizationTicket signatures.
///
/// This script is designed to be called from Rust tests via JSON exchange:
///   1. Rust writes input JSON
///   2. This script reads it, computes the hash using the canonical `abi.encode`
///   3. Writes the result to output JSON
///
/// This makes the on-chain encoding the single source of truth.
contract CanonicalTicketHash is Script {
    using stdJson for string;

    struct TicketInput {
        uint8 ticketType;
        uint64 nonce;
        bytes32 contextHash;
        uint64 activationHeight;
        bytes newMeasurement;
        bytes pqPubkey;
        bytes32 forkSpecHash;
        uint32 newHeaderVersion;
    }

    struct HashOutput {
        bytes32 hash;
    }

    function run() external {
        string memory inputPath = vm.envString("INPUT_JSON");
        string memory outputPath = vm.envString("OUTPUT_JSON");

        string memory json = vm.readFile(inputPath);

        // Read fields individually for robustness
        uint8 ticketType = uint8(json.readUint(".ticketType"));
        uint64 nonce = uint64(json.readUint(".nonce"));
        bytes32 contextHash = json.readBytes32(".contextHash");
        uint64 activationHeight = uint64(json.readUint(".activationHeight"));
        bytes memory newMeasurement = json.readBytes(".newMeasurement");
        bytes memory pqPubkey = json.readBytes(".pqPubkey");
        bytes32 forkSpecHash = json.readBytes32(".forkSpecHash");
        uint32 newHeaderVersion = uint32(json.readUint(".newHeaderVersion"));

        bytes32 computed;

        if (ticketType == 0) {
            computed = keccak256(
                abi.encode(
                    ticketType,
                    nonce,
                    contextHash,
                    activationHeight,
                    newMeasurement,
                    pqPubkey,
                    bytes32(0),
                    uint32(0)
                )
            );
        } else if (ticketType == 1) {
            computed = keccak256(
                abi.encode(
                    ticketType,
                    nonce,
                    contextHash,
                    activationHeight,
                    newMeasurement,
                    pqPubkey,
                    forkSpecHash,
                    newHeaderVersion
                )
            );
        } else {
            revert("Unsupported ticketType (must be 0 or 1)");
        }

        // Write result as simple JSON
        string memory jsonOut = string(abi.encodePacked('{"hash":"', vm.toString(computed), '"}'));
        vm.writeJson(jsonOut, outputPath);
    }
}
