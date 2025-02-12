//! An end-to-end example of using the SP1 SDK to generate a proof of a program that can be executed
//! or have a core proof generated.
//!
//! You can run this script using the following command:
//! ```shell
//! RUST_LOG=info cargo run --release -- --execute
//! ```
//! or
//! ```shell
//! RUST_LOG=info cargo run --release -- --prove
//! ```

use alloy_consensus::proofs::calculate_receipt_root;
use alloy_provider::{Provider, ProviderBuilder};
use alloy_rlp::Encodable;
use clap::Parser;
use santa_lib::{verify_hash_chain, PartialHeader};
use sp1_sdk::{include_elf, ProverClient, SP1Stdin};
use std::collections::HashMap;
use tracing::info;

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const FIBONACCI_ELF: &[u8] = include_elf!("fibonacci-program");

/// The arguments for the command.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(long, group = "mode")]
    execute: bool,

    #[clap(long, group = "mode")]
    prove: bool,

    #[clap(long, default_value = "http://localhost:8545")]
    rpc_url: String,

    #[clap(long, help = "start block")]
    start: u64,

    #[clap(long, help = "end block")]
    end: u64,

    #[clap(long, default_value_t = 100)]
    chunk_size: u64,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();

    // Parse the command line arguments.
    let args = Args::parse();

    let rpc_url = args.rpc_url.parse()?;
    info!("Setting up rpc with URL {}", rpc_url);
    let provider = ProviderBuilder::new().on_http(rpc_url);

    let total_blocks = args.end - args.start;
    let mut blocks = Vec::with_capacity(total_blocks.try_into().unwrap());

    for i in 0..total_blocks.div_ceil(args.chunk_size) {
        let start = args.start + i * args.chunk_size;
        let end = (start + args.chunk_size).min(args.end);

        info!("Fetching blocks {}-{}", start, end);

        let new_blocks = futures::future::try_join_all(
            (start..end).map(|block| provider.get_block_by_number(block.into(), false.into())),
        )
        .await?;

        blocks.extend(
            new_blocks
                .into_iter()
                .zip(start..end)
                .map(|(block, bn)| block.unwrap_or_else(|| panic!("Block #{} was empty", bn))),
        );
    }

    println!("blocks[0].transactions: {:?}", blocks[0].transactions);

    let mut tx_receipts = HashMap::new();

    let mut tx_hashes = blocks
        .iter()
        .map(|block| block.transactions.as_hashes().unwrap())
        .flatten();
    let mut tx_hash_batch = vec![];

    let total_txs: usize = blocks.iter().map(|block| block.transactions.len()).sum();
    let chunk_size: usize = args.chunk_size.try_into().unwrap();
    loop {
        let mut added = false;
        if let Some(hash) = tx_hashes.next() {
            added = true;
            tx_hash_batch.push(hash);
        }
        if tx_hash_batch.len() == chunk_size || !added {
            info!(
                "Fetching receipts {}-{} / {}",
                tx_receipts.len(),
                tx_receipts.len() + tx_hash_batch.len(),
                total_txs
            );
            let receipts = futures::future::try_join_all(
                tx_hash_batch
                    .iter()
                    .map(|hash| provider.get_transaction_receipt(**hash)),
            )
            .await?;

            tx_hash_batch
                .drain(..)
                .zip(receipts)
                .for_each(|(hash, receipt)| {
                    let receipt = receipt.unwrap().into_primitives_receipt();
                    tx_receipts.insert(*hash, receipt);
                });
        }

        if !added {
            break;
        }
    }

    let block = &blocks[0];
    println!(
        "block.header.receipts_root: {:?}",
        block.header.receipts_root
    );

    let first_hash = blocks[0].header.parent_hash;

    let res = verify_hash_chain(
        first_hash,
        blocks
            .iter()
            .map(|block| PartialHeader::from(&block.header)),
    );

    println!("res: {:?}", res);

    let block_receipts: Vec<_> = block
        .transactions
        .hashes()
        .into_iter()
        .map(|hash| tx_receipts.get(&hash).unwrap().inner.clone())
        .collect();

    let root = calculate_receipt_root(block_receipts.as_slice());

    println!("root: {:?}", root);

    println!("block.header: {:?}", block.header.inner);
    let mut encoded: Vec<u8> = vec![];
    block.header.encode(&mut encoded);

    let header = &block.header;

    let partial = PartialHeader::from(header);

    println!("header.length(): {:?}", header.length());
    println!("partial.length(): {:?}", partial.length());

    println!("header.hash_slow(): {:?}", header.hash_slow());
    println!("partial.hash_slow(): {:?}", partial.hash());

    // for tx_chunk in     {
    //     println!("tx_chunk: {:?}", tx_chunk);
    // }

    // let block = &blocks[0];
    // println!(
    //     "block.header.transactions_root: {:?}",
    //     block.header.transactions_root
    // );
    // println!(
    //     "block.calculate_transactions_root: {:?}",
    //     block.calculate_transactions_root()
    // );
    // let txs = &block.transactions.as_transactions().unwrap();
    // let tx = &txs[0];
    // println!("{:?}", tx.inner.tx_hash());

    // Setup the prover client.
    // let client = ProverClient::from_env();

    // TODO: Setup the inputs.
    // let mut stdin = SP1Stdin::new();
    // stdin.write_vec(buffer);

    // if args.execute {
    //     // Execute the program
    //     let (output, report) = client.execute(FIBONACCI_ELF, &stdin).run().unwrap();
    //     println!("Program executed successfully.");

    //     println!("hash1: {}", hex::encode(&output.as_slice()[0..32]));
    //     println!("hash2: {}", hex::encode(&output.as_slice()[32..64]));

    //     // Record the number of cycles executed.
    //     println!("Number of cycles: {}", report.total_instruction_count());
    // } else {
    //     // Setup the program for proving.
    //     let (pk, vk) = client.setup(FIBONACCI_ELF);

    //     // Generate the proof
    //     let proof = client
    //         .prove(&pk, &stdin)
    //         .run()
    //         .expect("failed to generate proof");

    //     println!("Successfully generated proof!");

    //     // Verify the proof.
    //     client.verify(&proof, &vk).expect("failed to verify proof");
    //     println!("Successfully verified proof!");
    // }

    Ok(())
}
