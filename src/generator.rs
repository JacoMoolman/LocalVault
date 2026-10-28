//! Random password generator using the operating system's secure RNG.

use crate::crypto::{CryptoError, random_below};

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.?/";
const AMBIGUOUS: &str = "Il1O0o";

pub const MIN_LENGTH: usize = 8;
pub const MAX_LENGTH: usize = 64;

#[derive(Clone, Debug)]
pub struct GenOptions {
    pub length: usize,
    pub lower: bool,
    pub upper: bool,
    pub digits: bool,
    pub symbols: bool,
    pub avoid_ambiguous: bool,
}

impl Default for GenOptions {
    fn default() -> Self {
        GenOptions { length: 20, lower: true, upper: true, digits: true, symbols: true, avoid_ambiguous: true }
    }
}

fn set(chars: &str, avoid_ambiguous: bool) -> Vec<char> {
    chars.chars().filter(|c| !avoid_ambiguous || !AMBIGUOUS.contains(*c)).collect()
}

fn pick(chars: &[char]) -> Result<char, CryptoError> {
    Ok(chars[random_below(chars.len() as u32)? as usize])
}

/// Generates a password containing at least one character from every chosen set.
pub fn generate(opts: &GenOptions) -> Result<String, CryptoError> {
    let mut sets: Vec<Vec<char>> = Vec::new();
    if opts.lower {
        sets.push(set(LOWER, opts.avoid_ambiguous));
    }
    if opts.upper {
        sets.push(set(UPPER, opts.avoid_ambiguous));
    }
    if opts.digits {
        sets.push(set(DIGITS, opts.avoid_ambiguous));
    }
    if opts.symbols {
        sets.push(set(SYMBOLS, opts.avoid_ambiguous));
    }
    if sets.is_empty() {
        sets.push(set(LOWER, opts.avoid_ambiguous));
    }
    let length = opts.length.clamp(MIN_LENGTH, MAX_LENGTH).max(sets.len());
    let all: Vec<char> = sets.iter().flatten().copied().collect();

    let mut out: Vec<char> = Vec::with_capacity(length);
    for s in &sets {
        out.push(pick(s)?);
    }
    while out.len() < length {
        out.push(pick(&all)?);
    }
    // Fisher-Yates shuffle so the guaranteed characters are not always first.
    for i in (1..out.len()).rev() {
        let j = random_below((i + 1) as u32)? as usize;
        out.swap(i, j);
    }
    Ok(out.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn respects_length_and_sets() {
        let opts = GenOptions { length: 32, ..Default::default() };
        for _ in 0..200 {
            let p = generate(&opts).unwrap();
            assert_eq!(p.chars().count(), 32);
            assert!(p.chars().any(|c| c.is_ascii_lowercase()));
            assert!(p.chars().any(|c| c.is_ascii_uppercase()));
            assert!(p.chars().any(|c| c.is_ascii_digit()));
            assert!(p.chars().any(|c| SYMBOLS.contains(c)));
            assert!(!p.chars().any(|c| AMBIGUOUS.contains(c)));
        }
    }

    #[test]
    fn digits_only() {
        let opts = GenOptions { length: 10, lower: false, upper: false, digits: true, symbols: false, avoid_ambiguous: false };
        let p = generate(&opts).unwrap();
        assert!(p.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn passwords_differ() {
        let opts = GenOptions::default();
        assert_ne!(generate(&opts).unwrap(), generate(&opts).unwrap());
    }

    #[test]
    fn length_is_clamped() {
        let p = generate(&GenOptions { length: 2, ..Default::default() }).unwrap();
        assert_eq!(p.chars().count(), MIN_LENGTH);
    }
}
