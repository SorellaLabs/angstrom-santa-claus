use alloy_primitives::{address, Address};
use alloy_provider::{Provider, ProviderBuilder};

use clap::Parser;
use santa_lib::{testing::random::LogInjector, Cache, SmolBlock};
use sp1_sdk::{include_elf, ProverClient, SP1Stdin};
use std::collections::HashMap;
use tracing::info;

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
const SANTA_ELF: &[u8] = include_elf!("santa-program");

const ANGSTROM: Address = address!("0x3FcA107f4F20c8E240078BFAA5A3bEF952111e4e");
const ASSETS: &[Address] = &[
    address!("0x4a00E1790CD32D4B20b4231b556e04E4f5C3F4BF"),
    address!("0xc62cAe6ed0b08e88863E4b3b3e5625C02Cbe5Af6"),
    address!("0x75E08A73Cc749846252AeD87e30a1fF9799907Af"),
    address!("0x569DBE15E6dB8B4FDA83170f797ee54901C8B41f"),
];

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
    chunk_size: usize,

    #[clap(long, default_value_t = 5)]
    log_every: usize,

    #[clap(long, default_value_t = 0.05)]
    skip_prob: f32,

    #[clap(long, default_value_t = 0.85)]
    solo_prob: f32,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();

    let mut cache = Cache::new(".cache/store.json");

    // Parse the command line arguments.
    let args = Args::parse();

    let provider: Box<dyn Provider> =
        if args.rpc_url.starts_with("http://") || args.rpc_url.starts_with("https://") {
            let rpc_url = args.rpc_url.parse()?;
            info!("Setting up RPC over HTTP with url: {:?}", rpc_url);
            Box::new(ProviderBuilder::new().on_http(rpc_url))
        } else {
            assert!(
                args.rpc_url.ends_with(".ipc"),
                "Expected ipc/http url got: {:?}",
                args.rpc_url
            );
            let rpc_url = args.rpc_url.into();
            info!("Setting up RPC with IPC url: {:?}", rpc_url);
            let ipc_provider = ProviderBuilder::new().on_ipc(rpc_url).await?;
            Box::new(ipc_provider)
        };

    let (start, end) = (args.start, args.end);

    info!("Fetching blocks");

    let block_nums_to_fetch = (start..end)
        .filter_map(|bn| match cache.get_block(bn.into()) {
            Some(_) => None,
            None => Some(bn),
        })
        .collect::<Vec<_>>();

    // Fetch blocks
    for (i, blocks) in block_nums_to_fetch.chunks(args.chunk_size).enumerate() {
        info!(
            "Fetching blocks {}-{} / {}",
            i * args.chunk_size,
            i * args.chunk_size + blocks.len(),
            block_nums_to_fetch.len()
        );

        let new_blocks = futures::future::try_join_all(
            blocks
                .into_iter()
                .map(|&block| provider.get_block_by_number(block.into(), false.into())),
        )
        .await?;

        cache.append_blocks(new_blocks.into_iter().zip(blocks).map(|(block, bn)| {
            let block = block.unwrap_or_else(|| panic!("Block #{} was empty", bn));
            let txs = block
                .transactions
                .as_hashes()
                .map_or_else(Vec::new, Vec::from);
            SmolBlock {
                header: block.header.into(),
                txs,
            }
        }));

        cache.save();
    }

    info!("Fetching receipts");

    let mut rng = rand::rng();
    use rand::distr::Distribution;
    let skip_rng = rand::distr::Bernoulli::new(args.skip_prob.into()).unwrap();

    let summary_blocks: Vec<_> = (start..end)
        .step_by(args.log_every)
        .filter(|_| !skip_rng.sample(&mut rng))
        .collect();

    let tx_hashes = summary_blocks
        .iter()
        .map(|bn| *bn)
        .map(|bn: u64| {
            let txs = cache.get_block(bn).unwrap().txs.clone();
            let already_fetched = cache.receipts.get(&bn).map_or(0, Vec::len);
            txs.into_iter()
                .skip(already_fetched)
                .map(move |hash| (bn, hash))
        })
        .flatten()
        .collect::<Vec<_>>();

    let mut offset = 0;
    for tx_hash_batch in tx_hashes.chunks(args.chunk_size) {
        info!(
            "Fetching receipts {}-{} / {}",
            offset,
            offset + tx_hash_batch.len(),
            tx_hashes.len()
        );
        offset += tx_hash_batch.len();

        let receipts = futures::future::try_join_all(
            tx_hash_batch
                .iter()
                .map(|(_, hash)| provider.get_transaction_receipt(*hash)),
        )
        .await?;

        tx_hash_batch
            .iter()
            .zip(receipts)
            .for_each(|((bn, _), receipt)| {
                let receipt = receipt.unwrap().into_primitives_receipt();
                cache.append_receipt(*bn, receipt.into_inner());
            });
        cache.save();
    }

    cache.save();

    // From this point on `synthetic_blocks` no longer represents real or even valid headers.
    let mut synthetic_blocks: Vec<_> = (start..end)
        .map(|bn| {
            let header = cache.get_block(bn).unwrap().header.clone();
            let receipts = summary_blocks
                .binary_search(&bn)
                .ok()
                .map(|_| cache.receipts.get(&bn).unwrap().clone());
            (header, receipts)
        })
        .collect();

    let mut log_injector = LogInjector::new(ANGSTROM, ASSETS.into(), args.solo_prob.into());
    let mut parent_hash = synthetic_blocks[0].0.parent_hash;
    for (header, receipts) in synthetic_blocks.iter_mut() {
        header.parent_hash = parent_hash;
        if let Some(receipts) = receipts {
            log_injector.inject_random_log(header, receipts);
        }
        parent_hash = header.hash_slow();
    }
    // log_injector.into_oracle

    // let fee_entry_oracle = inject_fee_summaries(
    //     summary_blocks,
    //     |bn| cache.get_header_receipt_pair(bn).unwrap(),
    //     ANGSTROM,
    //     Vec::from(ASSETS),
    //     args.solo_prob,
    // );

    if args.execute {
        // let client = ProverClient::from_env();

        // use alloy_rlp::Encodable;

        // let mut stdin = SP1Stdin::new();

        // let headers = blocks
        //     .into_iter()
        //     .map(|b| {
        //         let header = b.header.inner;
        //         let mut encoded = Vec::<u8>::with_capacity(header.length());
        //         header.encode(&mut encoded);
        //         encoded
        //     })
        //     .collect::<Vec<_>>();
        // let headers = headers.concat();

        // stdin.write_vec(headers);

        // // Execute the program
        // let (output, report) = client.execute(SANTA_ELF, &stdin).run().unwrap();
        // println!("Program executed successfully.");

        // println!("start: {}", hex::encode(&output.as_slice()[0..32]));
        // println!("end: {}", hex::encode(&output.as_slice()[32..64]));

        // // Record the number of cycles executed.
        // println!("Number of cycles: {}", report.total_instruction_count());
    }
    //else {
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
    info!("Done, shutting off");

    Ok(())
}
