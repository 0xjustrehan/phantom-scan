/// BGP Live Country & Region CIDR Routing Intelligence
///
/// Downloads, decompresses, caches, and parses live BGP prefix allocations from iptoasn.com.
/// Decomposes country/region IP boundaries into optimal summarized CIDR blocks.

use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::{Duration, SystemTime};
use flate2::read::GzDecoder;

pub const BGP_URL: &str = "https://iptoasn.com/data/ip2country-v4.tsv.gz";

pub struct GeoDatabase;

impl GeoDatabase {
    /// Expanded regions and continent groupings
    pub fn get_region_countries(name: &str) -> Option<&'static [&'static str]> {
        match name.to_lowercase().replace(' ', "_").as_str() {
            "slavic" => Some(&[
                "BY", "BA", "BG", "HR", "CZ", "ME", "MK", "PL", "RU", "RS", "SK", "SI", "UA",
            ]),
            "europe" => Some(&[
                "AL", "AD", "AT", "BY", "BE", "BA", "BG", "HR", "CY", "CZ", "DK", "EE", "FI",
                "FR", "DE", "GR", "HU", "IS", "IE", "IT", "XK", "LV", "LI", "LT", "LU", "MT",
                "MD", "MC", "ME", "NL", "MK", "NO", "PL", "PT", "RO", "RU", "SM", "RS", "SK",
                "SI", "ES", "SE", "CH", "TR", "UA", "GB", "VA", "GL", "JE", "GG", "IM", "FO",
            ]),
            "asia" => Some(&[
                "AF", "AM", "AZ", "BH", "BD", "BT", "BN", "KH", "CN", "GE", "IN", "ID", "IR",
                "IQ", "IL", "JP", "JO", "KZ", "KW", "KG", "LA", "LB", "MY", "MV", "MN", "MM",
                "NP", "KP", "OM", "PK", "PS", "PH", "QA", "SA", "SG", "KR", "LK", "SY", "TW",
                "TJ", "TH", "TL", "TM", "AE", "UZ", "VN", "YE", "HK", "MO",
            ]),
            "africa" => Some(&[
                "DZ", "AO", "BJ", "BW", "BF", "BI", "CV", "CM", "CF", "TD", "KM", "CG", "CD",
                "DJ", "EG", "GQ", "ER", "SZ", "ET", "GA", "GM", "GH", "GN", "GW", "CI", "KE",
                "LS", "LR", "LY", "MG", "MW", "ML", "MR", "MU", "MA", "MZ", "NA", "NE", "NG",
                "RW", "ST", "SN", "SC", "SL", "SO", "ZA", "SS", "SD", "TZ", "TG", "TN", "UG",
                "ZM", "ZW",
            ]),
            "north_america" | "na" => Some(&[
                "AG", "BS", "BB", "BZ", "CA", "CR", "CU", "DM", "DO", "SV", "GD", "GT", "HT",
                "HN", "JM", "MX", "NI", "PA", "KN", "LC", "VC", "TT", "US",
            ]),
            "south_america" | "sa" => Some(&[
                "AR", "BO", "BR", "CL", "CO", "EC", "GY", "PY", "PE", "SR", "UY", "VE",
            ]),
            "oceania" => Some(&[
                "AU", "FJ", "KI", "MH", "FM", "NR", "NZ", "PW", "PG", "WS", "SB", "TO", "TV",
                "VU",
            ]),
            _ => None,
        }
    }

    /// Path to local cached BGP database
    pub fn cache_path() -> PathBuf {
        let home = std::env::var("USERPROFILE")
            .or_else(|_| std::env::var("HOME"))
            .unwrap_or_else(|_| ".".to_string());
        let mut dir = PathBuf::from(home);
        dir.push(".phantom-scan");
        dir.push("cache");
        let _ = fs::create_dir_all(&dir);
        dir.push("ip2country-v4.tsv");
        dir
    }

    /// Check if cached routing table exists and is younger than 24 hours
    pub fn is_cache_fresh() -> bool {
        let path = Self::cache_path();
        if let Ok(meta) = fs::metadata(&path) {
            if let Ok(modified) = meta.modified() {
                if let Ok(elapsed) = SystemTime::now().duration_since(modified) {
                    return elapsed < Duration::from_secs(86400);
                }
            }
        }
        false
    }

    /// Download and refresh live BGP database
    pub async fn download_database() -> Result<PathBuf, String> {
        let cache = Self::cache_path();
        println!("[*] Downloading live BGP Routing Table from {}...", BGP_URL);

        let response = reqwest::get(BGP_URL)
            .await
            .map_err(|e| format!("HTTP request failed: {}", e))?;

        if !response.status().is_success() {
            return Err(format!("Server returned HTTP {}", response.status()));
        }

        let compressed_bytes = response
            .bytes()
            .await
            .map_err(|e| format!("Failed to read response body: {}", e))?;

        println!("    Decompressing BGP table ({} bytes gz)...", compressed_bytes.len());
        let mut decoder = GzDecoder::new(&compressed_bytes[..]);
        let mut uncompressed = Vec::new();
        decoder
            .read_to_end(&mut uncompressed)
            .map_err(|e| format!("Gzip decompression failed: {}", e))?;

        let mut file = File::create(&cache).map_err(|e| format!("Failed to write cache: {}", e))?;
        file.write_all(&uncompressed)
            .map_err(|e| format!("Failed to flush cache file: {}", e))?;

        println!("[+] BGP Routing Table successfully cached to {}", cache.display());
        Ok(cache)
    }

    /// Summarize arbitrary start_ip and end_ip range into optimal CIDR blocks
    pub fn summarize_range_v4(start: Ipv4Addr, end: Ipv4Addr) -> Vec<ipnet::Ipv4Net> {
        let mut networks = Vec::new();
        let mut cur = u32::from(start) as u64;
        let end_u64 = u32::from(end) as u64;

        while cur <= end_u64 {
            let max_size = end_u64 - cur + 1;
            let align_bits = if cur == 0 { 32 } else { cur.trailing_zeros().min(32) };

            let mut prefix_len = 32 - align_bits;
            while (1u64 << (32 - prefix_len)) > max_size {
                prefix_len += 1;
            }

            let net_size = 1u64 << (32 - prefix_len);
            if let Ok(net) = ipnet::Ipv4Net::new(Ipv4Addr::from(cur as u32), prefix_len as u8) {
                networks.push(net);
            }
            cur += net_size;
        }

        networks
    }

    /// Fetch BGP CIDRs for a specific Country Code (e.g. "US", "DE") or Region (e.g. "slavic", "europe")
    pub async fn fetch_cidrs(
        target: &str,
        exclude_countries: &[String],
    ) -> Result<(String, Vec<String>), String> {
        let target_clean = target.trim();
        let (countries, label_name): (HashSet<String>, String) = if target_clean.len() == 2 {
            let code = target_clean.to_uppercase();
            let mut set = HashSet::new();
            set.insert(code.clone());
            (set, format!("Country_{}", code))
        } else if let Some(country_list) = Self::get_region_countries(target_clean) {
            let set: HashSet<String> = country_list.iter().map(|s| s.to_string()).collect();
            let key = target_clean.to_lowercase().replace(' ', "_");
            (set, key)
        } else {
            return Err(format!(
                "Invalid country code or region '{}'. Use 2-letter ISO (e.g. 'US', 'RU') or region ('europe', 'asia', 'slavic', 'north_america', 'south_america', 'africa', 'oceania')",
                target
            ));
        };

        // Filter excluded countries
        let exclude_set: HashSet<String> = exclude_countries
            .iter()
            .map(|s| s.trim().to_uppercase())
            .filter(|s| !s.is_empty())
            .collect();

        let active_countries: HashSet<String> = countries
            .into_iter()
            .filter(|c| !exclude_set.contains(c))
            .collect();

        if active_countries.is_empty() {
            return Err("All target countries were excluded.".to_string());
        }

        // Ensure database is available
        let cache_file = if Self::is_cache_fresh() {
            Self::cache_path()
        } else {
            Self::download_database().await?
        };

        println!(
            "[*] Parsing BGP routes for {} countries (Region: {})...",
            active_countries.len(),
            label_name
        );

        let file = File::open(&cache_file).map_err(|e| format!("Failed to open cache: {}", e))?;
        let reader = BufReader::new(file);

        let mut cidrs = HashSet::new();

        for line in reader.lines() {
            let line = line.map_err(|e| format!("Read error: {}", e))?;
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            let parts: Vec<&str> = trimmed.split('\t').collect();
            if parts.len() >= 3 {
                let cc = parts[2].trim().to_uppercase();
                if active_countries.contains(&cc) {
                    if let (Ok(start), Ok(end)) = (
                        Ipv4Addr::from_str(parts[0].trim()),
                        Ipv4Addr::from_str(parts[1].trim()),
                    ) {
                        for net in Self::summarize_range_v4(start, end) {
                            cidrs.insert(net.to_string());
                        }
                    }
                }
            }
        }

        let mut sorted: Vec<String> = cidrs.into_iter().collect();
        sorted.sort();

        println!(
            "[+] Generated {} optimal CIDR prefixes for {}.",
            sorted.len(),
            label_name
        );

        Ok((label_name, sorted))
    }
}
