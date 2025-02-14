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

use alloy_eips::Encodable2718;
use alloy_provider::{Provider, ProviderBuilder};

use clap::Parser;
use santa_lib::{
    receipt_trie::{get_proof_for_receipt, receipt_trie_root_from_proof},
    verify_hash_chain, PartialHeader,
};
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
    start: Option<u64>,

    #[clap(long, help = "end block")]
    end: Option<u64>,

    #[clap(long, default_value_t = 100)]
    chunk_size: u64,

    #[clap(long)]
    target: Option<u64>,

    #[clap(long)]
    skip_receipts: bool,

    #[clap(long, group = "minmax")]
    min: bool,

    #[clap(long, group = "minmax")]
    max: bool,

    #[clap(long, default_value_t = 0)]
    index: u32,
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

    let (start, end) = if let Some(target) = args.target {
        (target, target + 1)
    } else {
        args.start.zip(args.end).unwrap()
    };

    let total_blocks = end - start;
    let mut blocks = Vec::with_capacity(total_blocks.try_into().unwrap());

    // Fetch blocks
    for i in 0..total_blocks.div_ceil(args.chunk_size) {
        let chunk_start = start + i * args.chunk_size;
        let chunk_end = (chunk_start + args.chunk_size).min(end);

        info!("Fetching blocks {}-{}", chunk_start, chunk_end);

        let new_blocks = futures::future::try_join_all(
            (chunk_start..chunk_end)
                .map(|block| provider.get_block_by_number(block.into(), false.into())),
        )
        .await?;

        blocks.extend(
            new_blocks
                .into_iter()
                .zip(chunk_start..chunk_end)
                .map(|(block, bn)| block.unwrap_or_else(|| panic!("Block #{} was empty", bn))),
        );
    }

    // Determine target block
    let target_block = args.target.or_else(|| {
        if args.max {
            blocks.iter().max_by_key(|b| b.transactions.len())
        } else if args.min {
            blocks
                .iter()
                .filter(|b| b.transactions.len() >= 1)
                .min_by_key(|b| b.transactions.len())
        } else {
            None
        }
        .map(|b| b.header.number)
    });

    // Fetch receipts for all blocks *or* just target
    let mut tx_receipts = HashMap::new();
    let tx_hashes = blocks
        .iter()
        .filter(|b| target_block.map_or(true, |n| b.header.number == n))
        .map(|block| block.transactions.as_hashes().unwrap())
        .flatten()
        .collect::<Vec<_>>();
    let total_txs: usize = tx_hashes.len();
    let chunk_size: usize = args.chunk_size.try_into().unwrap();
    if !args.skip_receipts {
        for tx_hash_batch in tx_hashes.chunks(chunk_size) {
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
                .iter()
                .zip(receipts)
                .for_each(|(hash, receipt)| {
                    let receipt = receipt.unwrap().into_primitives_receipt();
                    tx_receipts.insert(*hash, receipt);
                });
        }
    }

    // Hash chain stuff
    let first_hash = blocks[0].header.parent_hash;
    let res = verify_hash_chain(
        first_hash,
        blocks
            .iter()
            .map(|block| PartialHeader::from(&block.header)),
    );
    assert_eq!(
        res.unwrap(),
        blocks.iter().last().unwrap().header.hash,
        "hash chain mismatch"
    );
    println!("✅ hash chain verified");

    let block_index = target_block.map_or(0, |t| t - start) as usize;
    let block = &blocks[block_index];
    info!(
        "Targeting: {} (total tx: {})",
        block_index + start as usize,
        block.transactions.len()
    );
    println!(
        "block.header.receipts_root: {:?}",
        block.header.receipts_root
    );

    let block_receipts: Vec<_> = block
        .transactions
        .hashes()
        .into_iter()
        .map(|hash| tx_receipts.get(&hash).unwrap().inner.clone())
        .collect();

    block_receipts.iter().enumerate().for_each(|(i, receipt)| {
        let proof = get_proof_for_receipt(block_receipts.as_slice(), i as u32);
        assert_eq!(
            block.header.receipts_root,
            receipt_trie_root_from_proof(&proof, {
                let mut buf = Vec::<u8>::new();
                receipt.encode_2718(&mut buf);
                buf
            }),
            "Receipt #{} failed to match",
            i
        );
    });

    println!(
        "✅ {}/{} proofs verified",
        block_receipts.len(),
        block_receipts.len()
    );

    // block_receipts[0].encode_2718

    // let res = verify_proof(
    //     block.header.receipts_root,
    //     key.clone(),
    //     Some(encode_2718(&block_receipts[args.index as usize])),
    //     proof
    //         .iter()
    //         .filter(|(k, _)| {
    //             if *k != key {
    //                 true
    //             } else {
    //                 println!("k: {:?}", k);
    //                 false
    //             }
    //         })
    //         .map(|(k, x)| {
    //             println!("{:?}: {}", k, x);
    //             x
    //         }),
    // );
    // println!("res: {:?}", res);

    // for i in 0..400u16 {
    //     let encoded_i = rlp_encode(i);
    //     println!("{} -> {}", i, hex::encode(&encoded_i));
    // }

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
/*

REAL

f9 - list
    len: 0112
    .0:
        82 - str
        0x2080

    b9010c<receipt>

MINE

f9 - list
    len: 0112
    2080b9010c


*/
