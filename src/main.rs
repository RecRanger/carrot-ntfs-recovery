mod ntfs_logic;

use anyhow::Result;
use clap::Parser;
use log::{debug, info};
use memmap2::Mmap;
use std::{
    fs::File,
    io::{BufWriter, Write},
};

use ntfs_logic::scan_ntfs_image;

#[derive(Parser, Debug)]
#[command(author, version, about = "NTFS filesystem recovery/forensics tool")]
struct Cli {
    /// Input disk image (raw)
    #[arg(short, long)]
    input: String,

    /// Output NDJSON file
    #[arg(short, long)]
    output: String,
}

fn main() -> Result<()> {
    env_logger::init();

    let cli = Cli::parse();

    let input_file = File::open(&cli.input)?;
    debug!("Opened input file: {}", &cli.input);
    // Advisory lock - prevents writes by cooperating processes.
    // Reduces a risk from unsafe mmap (e.g., if file is shortened or deleted during operation).
    input_file.lock_shared()?;
    debug!("Locked input file: {}", &cli.input);

    let disk_image_buffer_mmap = unsafe { Mmap::map(&input_file)? };

    // Optimization: Inform the kernel that it's fine to dump old pages after we're past,
    // and that we'll be requesting forward-looking pages continuously.
    disk_image_buffer_mmap.advise(memmap2::Advice::Sequential)?;

    let output_file = File::create(&cli.output)?;
    let mut output_file_writer = BufWriter::new(output_file);

    let mut file_count: u64 = 0;

    info!("Starting to process NTFS image's file entries.");

    for ntfs_output_entry in scan_ntfs_image(&disk_image_buffer_mmap) {
        let json = serde_json::to_string(&ntfs_output_entry)?;
        writeln!(output_file_writer, "{json}")?;
        file_count += 1;

        if file_count % 1000 == 0 {
            info!(
                "Processed {} file entries. Last file position: {} = {:.3} GiB",
                file_count,
                ntfs_output_entry.mft_offset,
                (ntfs_output_entry.mft_offset as f64 / (1024.0 * 1024.0 * 1024.0))
            );
        }
    }

    info!("Processed a total of {} file entries.", file_count);

    Ok(())
}
