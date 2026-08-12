use crate::error::{VaultError, VaultResult};
use rand::{seq::SliceRandom, Rng};
use rand::rngs::OsRng;
use serde::Deserialize;

/// ~470 curated words; swap in the full EFF Large Wordlist (7776 words,
/// log2(7776) ~= 12.9 bits/word) by replacing assets/wordlist.txt, no code change needed.
/// https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt
const WORDLIST: &str = include_str!("../../assets/wordlist.txt");

#[derive(Deserialize)]
pub struct PasswordOptions {
    #[serde(default = "default_length")]
    pub length:          usize,
    #[serde(default = "default_true")]
    pub uppercase:       bool,
    #[serde(default = "default_true")]
    pub lowercase:       bool,
    #[serde(default = "default_true")]
    pub numbers:         bool,
    #[serde(default = "default_true")]
    pub symbols:         bool,
    #[serde(default)]
    pub avoid_ambiguous: bool,
    #[serde(default = "default_one")]
    pub min_numbers:     usize,
    #[serde(default = "default_one")]
    pub min_symbols:     usize,
}

fn default_length() -> usize { 20 }
fn default_true() -> bool { true }
fn default_one() -> usize { 1 }

impl Default for PasswordOptions {
    fn default() -> Self {
        PasswordOptions {
            length: 20, uppercase: true, lowercase: true, numbers: true, symbols: true,
            avoid_ambiguous: false, min_numbers: 1, min_symbols: 1,
        }
    }
}

#[derive(Deserialize)]
pub struct PassphraseOptions {
    #[serde(default = "default_word_count")]
    pub word_count:     usize,
    #[serde(default = "default_separator")]
    pub separator:      String,
    #[serde(default)]
    pub capitalize:     bool,
    #[serde(default)]
    pub include_number: bool,
}

fn default_word_count() -> usize { 4 }
fn default_separator() -> String { "-".to_string() }

impl Default for PassphraseOptions {
    fn default() -> Self {
        PassphraseOptions { word_count: 4, separator: "-".to_string(), capitalize: false, include_number: false }
    }
}

#[tauri::command]
pub fn generate_password(opts: Option<PasswordOptions>) -> VaultResult<String> {
    let opts = opts.unwrap_or_default();

    if opts.length < 4 {
        return Err(VaultError::Internal("minimum length is 4".into()));
    }

    const AMBIGUOUS: &str = "0Ol1I";
    let filter = |s: &str| -> Vec<char> {
        s.chars().filter(|c| !opts.avoid_ambiguous || !AMBIGUOUS.contains(*c)).collect()
    };

    let uppers:  Vec<char> = filter("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    let lowers:  Vec<char> = filter("abcdefghijklmnopqrstuvwxyz");
    let digits:  Vec<char> = filter("0123456789");
    let symbols: Vec<char> = "!@#$%^&*()-_=+[]{}|;:,.<>?".chars().collect();

    if opts.min_numbers + opts.min_symbols > opts.length {
        return Err(VaultError::Internal(
            "min_numbers + min_symbols cannot exceed the requested length".into(),
        ));
    }

    let mut rng = OsRng;
    let mut chars: Vec<char> = Vec::with_capacity(opts.length);

    if opts.numbers {
        for _ in 0..opts.min_numbers {
            chars.push(*digits.get(rng.gen_range(0..digits.len().max(1))).unwrap_or(&'0'));
        }
    }
    if opts.symbols {
        for _ in 0..opts.min_symbols {
            chars.push(*symbols.get(rng.gen_range(0..symbols.len())).unwrap_or(&'!'));
        }
    }

    let mut full_set: Vec<char> = Vec::new();
    if opts.uppercase { full_set.extend(&uppers); }
    if opts.lowercase { full_set.extend(&lowers); }
    if opts.numbers   { full_set.extend(&digits); }
    if opts.symbols   { full_set.extend(&symbols); }

    if full_set.is_empty() {
        return Err(VaultError::Internal("no character set selected".into()));
    }

    while chars.len() < opts.length {
        chars.push(full_set[rng.gen_range(0..full_set.len())]);
    }

    chars.shuffle(&mut rng); // otherwise forced digit/symbol chars always sort first

    Ok(chars.into_iter().collect())
}

#[tauri::command]
pub fn generate_passphrase(opts: Option<PassphraseOptions>) -> VaultResult<String> {
    let opts = opts.unwrap_or_default();

    if opts.word_count == 0 {
        return Err(VaultError::Internal("word_count must be at least 1".into()));
    }

    let words: Vec<&str> = WORDLIST.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    if words.is_empty() {
        return Err(VaultError::Internal("wordlist is empty (this is a bug, not a user error)".into()));
    }

    let mut rng = OsRng;
    let mut chosen: Vec<String> = (0..opts.word_count)
        .map(|_| {
            let w = words[rng.gen_range(0..words.len())];
            if opts.capitalize {
                let mut c = w.chars();
                match c.next() {
                    Some(first) => first.to_uppercase().collect::<String>() + c.as_str(),
                    None => w.to_string(),
                }
            } else {
                w.to_string()
            }
        })
        .collect();

    if opts.include_number {
        // matches Bitwarden desktop's default: append a 2-digit number to one word
        let idx = rng.gen_range(0..chosen.len());
        let num: u32 = rng.gen_range(0..100);
        chosen[idx] = format!("{}{:02}", chosen[idx], num);
    }

    Ok(chosen.join(&opts.separator))
}
