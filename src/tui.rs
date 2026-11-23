use std::fs::File;
use std::io::{self, Write};
use std::path::Path;
use colored::*;

use crate::cli::Cli;
use crate::evasion::OsProfile;
use crate::geo::GeoDatabase;

fn prompt_line(prompt: &str, default: Option<&str>) -> String {
    if let Some(def) = default {
        print!("{} [{}] > ", prompt.cyan().bold(), def.yellow());
    } else {
        print!("{} > ", prompt.cyan().bold());
    }
    let _ = io::stdout().flush();

    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_ok() {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            default.unwrap_or("").to_string()
        } else {
            trimmed.to_string()
        }
    } else {
        default.unwrap_or("").to_string()
    }
}

pub async fn run_interactive_wizard(default_args: Cli) -> Result<Cli, Box<dyn std::error::Error>> {
    let mut args = default_args;

    println!("\n{}", "┌───────────────────────────────────────────────────────────────────────────┐".bright_black());
    println!("│                     {}                     │", "PHANTOM-SCAN INTERACTIVE OPERATOR WIZARD".bright_yellow().bold());
    println!("{}", "└───────────────────────────────────────────────────────────────────────────┘".bright_black());

    // ──────────────────────────────────────────────────────────────────────────
    // Step 1: Targets
    // ──────────────────────────────────────────────────────────────────────────
    println!("\n{}", "[STEP 1/7] Target Definition".green().bold());
    println!("  [1] Live BGP Geo-Routing (Country / Region CIDR prefix decomposition)");
    println!("  [2] Custom CIDR / IP Range / Single IP (manual input)");
    println!("  [3] Load Targets from File");

    let target_choice = prompt_line("Select target mode (1-3)", Some("1"));

    match target_choice.as_str() {
        "1" => {
            println!("\n  Available Regions: slavic, europe, asia, north_america, south_america, africa, oceania");
            println!("  Or enter 2-letter ISO country code: US, RU, DE, BR, GB, FR, CN, IN, etc.");
            let country_input = prompt_line("Target Country ISO or Region", Some("slavic"));
            let exclude_input = prompt_line("Exclude country codes (comma-separated, e.g. 'RU,BY' or leave blank)", Some(""));

            let excludes: Vec<String> = if exclude_input.is_empty() {
                Vec::new()
            } else {
                exclude_input.split(',').map(|s| s.trim().to_string()).collect()
            };

            println!("\n[*] Fetching and decomposing BGP prefixes for '{}'...", country_input.yellow());
            match GeoDatabase::fetch_cidrs(&country_input, &excludes).await {
                Ok((label, cidrs)) => {
                    let out_path = format!("{}_ranges.txt", label.to_lowercase());
                    let mut file = File::create(&out_path)?;
                    for cidr in &cidrs {
                        writeln!(file, "{}", cidr)?;
                    }
                    println!("[+] Successfully written {} CIDR blocks to {}", cidrs.len().to_string().green().bold(), out_path.yellow());
                    args.targets_file = Some(out_path);
                    args.target = None;
                    args.country = Some(country_input);
                    if !exclude_input.is_empty() {
                        args.exclude_country = Some(exclude_input);
                    }
                }
                Err(e) => {
                    eprintln!("[-] Error resolving BGP routes: {}", e.red());
                    return Err(e.into());
                }
            }
        }
        "2" => {
            let target_str = prompt_line("Enter target CIDR(s) or range(s) (comma-separated)", Some("192.168.1.0/24"));
            args.target = Some(target_str);
            args.targets_file = None;
        }
        "3" => {
            let file_str = prompt_line("Enter path to target file", Some("targets.txt"));
            if !Path::new(&file_str).exists() {
                eprintln!("[-] Warning: File '{}' does not currently exist on disk.", file_str.yellow());
            }
            args.targets_file = Some(file_str);
            args.target = None;
        }
        _ => {
            println!("[-] Invalid selection, defaulting to custom target.");
            let target_str = prompt_line("Enter target CIDR(s)", Some("192.168.1.0/24"));
            args.target = Some(target_str);
            args.targets_file = None;
        }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Step 2: Ports
    // ──────────────────────────────────────────────────────────────────────────
    println!("\n{}", "[STEP 2/7] Port Selection".green().bold());
    println!("  [1] RDP (3389)");
    println!("  [2] Quick RDP NLA (3389, Grab Banner + NLA/CredSSP Only + Bare IP:PORT)");
    println!("  [3] Quick SSH (22, Bare IP:PORT)");
    println!("  [4] Web HTTP/HTTPS (80,443)");
    println!("  [5] SMB (445)");
    println!("  [6] Top 17 Common (21,22,23,25,80,110,139,443,445,1433,3306,3389,5432,5900,6379,8080,8443)");
    println!("  [7] Custom Port List / Range");

    let port_choice = prompt_line("Select ports preset (1-7)", Some("1"));
    match port_choice.as_str() {
        "1" => args.ports = "3389".to_string(),
        "2" => {
            args.ports = "3389".to_string();
            args.banner = true;
            args.nla_only = true;
            args.bare = true;
        }
        "3" => {
            args.ports = "22".to_string();
            args.bare = true;
        }
        "4" => args.ports = "80,443".to_string(),
        "5" => args.ports = "445".to_string(),
        "6" => args.ports = "common".to_string(),
        "7" => {
            let custom_ports = prompt_line("Enter port list (e.g. '1-1024' or '80,8080,3389')", Some("3389"));
            args.ports = custom_ports;
        }
        _ => args.ports = "3389".to_string(),
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Step 3: Engine Mode
    // ──────────────────────────────────────────────────────────────────────────
    println!("\n{}", "[STEP 3/7] Scanning Engine Mode".green().bold());
    #[cfg(target_os = "linux")]
    {
        println!("  [1] AF_PACKET Zero-Copy (Recommended — Linux high-speed ring buffer)");
        println!("  [2] Raw-SYN (Standard raw socket injection)");
        println!("  [3] Stealth-Async (Non-root user-space async TCP connect)");

        let engine_choice = prompt_line("Select engine (1-3)", Some("1"));
        match engine_choice.as_str() {
            "1" => args.mode = "af-packet".to_string(),
            "2" => args.mode = "raw-syn".to_string(),
            "3" => args.mode = "stealth-async".to_string(),
            _ => args.mode = "af-packet".to_string(),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        println!("  [1] Raw-SYN (Wire-speed raw socket injection — Requires Admin)");
        println!("  [2] Stealth-Async (Universal user-space async TCP connect)");

        let engine_choice = prompt_line("Select engine (1-2)", Some("1"));
        match engine_choice.as_str() {
            "1" => args.mode = "raw-syn".to_string(),
            "2" => args.mode = "stealth-async".to_string(),
            _ => args.mode = "raw-syn".to_string(),
        }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Step 4: Transmission Rate (PPS)
    // ──────────────────────────────────────────────────────────────────────────
    println!("\n{}", "[STEP 4/7] Transmission Rate".green().bold());
    let rate_input = prompt_line("Target probe rate in Packets Per Second (pps)", Some(&args.rate.to_string()));
    if let Ok(rate_num) = rate_input.parse::<u64>() {
        args.rate = rate_num;
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Step 5: Banner Grabbing
    // ──────────────────────────────────────────────────────────────────────────
    println!("\n{}", "[STEP 5/7] Banner Grabbing".green().bold());
    let banner_default = if args.banner { "y" } else { "n" };
    let banner_input = prompt_line("Inspect & grab service banners on SYN-ACK? (y/n)", Some(banner_default));
    args.banner = banner_input.to_lowercase().starts_with('y');
    if args.nla_only {
        args.banner = true;
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Step 6: OS Camouflage Profile
    // ──────────────────────────────────────────────────────────────────────────
    println!("\n{}", "[STEP 6/7] OS Stack Camouflage Profile".green().bold());
    println!("  [1] Random (Jittered TTL, shuffled options, synthetic TSval)");
    println!("  [2] Windows 10/11 (RFC1323, WScale 8, MSS 1460)");
    println!("  [3] Linux (Kernel 5.x/6.x, WScale 7, MSS 1460)");
    println!("  [4] macOS (WScale 6, MSS 1440)");
    println!("  [5] Android");

    let profile_choice = prompt_line("Select profile (1-5)", Some("1"));
    match profile_choice.as_str() {
        "1" => args.profile = OsProfile::Random,
        "2" => args.profile = OsProfile::Windows,
        "3" => args.profile = OsProfile::Linux,
        "4" => args.profile = OsProfile::Macos,
        "5" => args.profile = OsProfile::Android,
        _ => args.profile = OsProfile::Random,
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Step 7: Output & Formatting
    // ──────────────────────────────────────────────────────────────────────────
    println!("\n{}", "[STEP 7/7] Output & Formatting".green().bold());
    let out_input = prompt_line("Output result file path", Some(&args.output_file));
    args.output_file = out_input;

    let bare_default = if args.bare { "y" } else { "n" };
    let bare_input = prompt_line("Save strictly as clean IP:PORT (no banner annotations)? (y/n)", Some(bare_default));
    args.bare = bare_input.to_lowercase().starts_with('y');

    let cooldown_input = prompt_line("Subnet anti-abuse cooldown in ms (0 = disabled)", Some(&args.cooldown_ms.to_string()));
    if let Ok(cd) = cooldown_input.parse::<u32>() {
        args.cooldown_ms = cd;
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Review Summary
    // ──────────────────────────────────────────────────────────────────────────
    println!("\n{}", "═══════════════════════════════════════════════════════════════════════════".bright_black());
    println!("  {} Configuration Review", "[*]".green().bold());
    println!("  Target:       {}", if let Some(ref f) = args.targets_file { format!("File [{}]", f).yellow() } else { args.target.as_deref().unwrap_or("none").yellow() });
    println!("  Ports:        {}", args.ports.cyan().bold());
    println!("  Engine:       {}", args.mode.to_uppercase().bright_magenta().bold());
    println!("  Rate:         {:.2}-kpps ({} pps)", (args.rate as f64) / 1000.0, args.rate.to_string().yellow().bold());
    println!("  Banner:       {}", if args.banner { "ENABLED".green().bold() } else { "DISABLED".bright_black() });
    if args.nla_only {
        println!("  NLA Filter:   {}", "ENABLED (Strictly save verified CredSSP targets)".bright_cyan().bold());
    }
    if args.bare {
        println!("  Output Form:  {}", "Clean IP:PORT (one per line)".bright_yellow().bold());
    }
    println!("  Profile:      {:?}", args.profile);
    if args.cooldown_ms == 0 {
        println!("  Cooldown:     {}", "DISABLED (Unrestricted line-rate like masscan)".yellow().bold());
    } else {
        println!("  Cooldown:     {} ms", args.cooldown_ms);
    }
    println!("  Output File:  {}", args.output_file.yellow());
    println!("{}", "═══════════════════════════════════════════════════════════════════════════".bright_black());

    let launch_confirm = prompt_line("Launch scan now? (Y/n)", Some("y"));
    if !launch_confirm.to_lowercase().starts_with('y') {
        println!("[-] Scan aborted by operator.");
        std::process::exit(0);
    }

    Ok(args)
}
