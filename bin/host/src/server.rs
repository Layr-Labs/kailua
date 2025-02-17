// Copyright 2024, 2025 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::args::KailuaHostArgs;
use alloy_primitives::B256;
use anyhow::anyhow;
use kailua_client::proving::ProvingError;
use kailua_common::proof::Proof;
use kailua_common::witness::StitchedBootInfo;
use kona_preimage::{BidirectionalChannel, HintWriter, OracleReader};
use tracing::info;

/// Starts the [PreimageServer] and the client program in separate threads. The client program is
/// ran natively in this mode.
///
/// ## Takes
/// - `cfg`: The host configuration.
///
/// ## Returns
/// - `Ok(exit_code)` if the client program exits successfully.
/// - `Err(_)` if the client program failed to execute, was killed by a signal, or the host program
///   exited first.
pub async fn start_server_and_native_client(
    args: KailuaHostArgs,
    precondition_validation_data_hash: B256,
    stitched_boot_info: Vec<StitchedBootInfo>,
    stitched_proofs: Vec<Proof>,
    prove_snark: bool,
    force_attempt: bool,
) -> Result<(), ProvingError> {
    // Instantiate data channels
    let hint = BidirectionalChannel::new().map_err(|e| ProvingError::OtherError(anyhow!(e)))?;
    let preimage = BidirectionalChannel::new().map_err(|e| ProvingError::OtherError(anyhow!(e)))?;
    // Create the server and start it.
    let server_task = args
        .kona
        .start_server(hint.host, preimage.host)
        .await
        .map_err(|e| ProvingError::OtherError(anyhow!(e)))?;
    // Start the client program in a separate child process.
    let program_task = tokio::spawn(kailua_client::proving::run_proving_client(
        args.boundless,
        OracleReader::new(preimage.client),
        HintWriter::new(hint.client),
        args.payout_recipient_address.unwrap_or_default(),
        precondition_validation_data_hash,
        stitched_boot_info,
        stitched_proofs,
        prove_snark,
        force_attempt,
        args.segment_limit,
        args.max_witness_size,
    ));
    // Execute both tasks and wait for them to complete.
    info!("Starting preimage server and client program.");
    let (_, client_result) = tokio::try_join!(server_task, program_task,)
        .map_err(|e| ProvingError::OtherError(anyhow!(e)))?;
    info!(target: "kona_host", "Preimage server and client program have joined.");
    // Return execution result
    client_result
}
