//! Per-rule hit counters, read from `nft -j list ruleset`.
//!
//! ufw writes its rules through iptables-nft on every current distribution, so the nft JSON view is
//! the most reliable source and needs no text parsing. Rules are matched to ufw rule numbers **by
//! position inside `ufw-user-input`**, which is the order ufw appends them in.
//!
//! That mapping is only trusted when the counts line up exactly. A `limit` rule becomes several
//! kernel rules, and an application profile becomes one rule per port, so alignment often fails —
//! in which case every count is reported as unavailable. Wrong numbers would be worse than none.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::core::rule::{Direction, Rule};

const INPUT_CHAIN: &str = "ufw-user-input";
const OUTPUT_CHAIN: &str = "ufw-user-output";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HitCounters {
    /// Packets matched per ufw rule number.
    pub per_rule: BTreeMap<u32, u64>,
    /// Total packets seen by each ufw chain, useful even when per-rule alignment fails.
    pub chain_totals: Vec<(String, u64)>,
    /// `false` means `per_rule` is empty on purpose.
    pub reliable: bool,
    /// Why the numbers are missing or approximate, shown in the UI.
    pub note: String,
}

impl HitCounters {
    pub fn unavailable(note: impl Into<String>) -> Self {
        Self {
            per_rule: BTreeMap::new(),
            chain_totals: Vec::new(),
            reliable: false,
            note: note.into(),
        }
    }

    pub fn get(&self, number: u32) -> Option<u64> {
        self.per_rule.get(&number).copied()
    }

    pub fn chain_total(&self, chain: &str) -> Option<u64> {
        self.chain_totals
            .iter()
            .find(|(name, _)| name == chain)
            .map(|(_, total)| *total)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NftRule {
    pub chain: String,
    pub packets: Option<u64>,
}

/// Extracts every rule in the nft JSON that carries a packet counter.
pub fn parse_nft_rules(json: &str) -> Vec<NftRule> {
    let Ok(root) = serde_json::from_str::<Value>(json) else {
        return Vec::new();
    };
    let Some(objects) = root.get("nftables").and_then(Value::as_array) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for object in objects {
        let Some(rule) = object.get("rule") else {
            continue;
        };
        let Some(chain) = rule.get("chain").and_then(Value::as_str) else {
            continue;
        };
        let mut packets = None;
        if let Some(exprs) = rule.get("expr").and_then(Value::as_array) {
            for expr in exprs {
                if let Some(counter) = expr.get("counter") {
                    packets = counter.get("packets").and_then(Value::as_u64);
                }
            }
        }
        out.push(NftRule {
            chain: chain.to_string(),
            packets,
        });
    }
    out
}

/// Sums the counters of one chain.
pub fn chain_total(rules: &[NftRule], chain: &str) -> u64 {
    rules
        .iter()
        .filter(|r| r.chain == chain)
        .filter_map(|r| r.packets)
        .sum()
}

/// Maps chain position to ufw rule numbers, or `None` when the lengths disagree.
pub fn align(rules: &[NftRule], chain: &str, numbers: &[u32]) -> Option<BTreeMap<u32, u64>> {
    let chain_rules: Vec<&NftRule> = rules.iter().filter(|r| r.chain == chain).collect();
    if chain_rules.len() != numbers.len() || numbers.is_empty() {
        return None;
    }
    let mut out = BTreeMap::new();
    for (rule, number) in chain_rules.iter().zip(numbers) {
        out.insert(*number, rule.packets.unwrap_or(0));
    }
    Some(out)
}

/// Full parse used by the backend: read the nft JSON and map it onto the rules we know about.
pub fn collect(json: &str, rules: &[Rule]) -> HitCounters {
    let parsed = parse_nft_rules(json);
    if parsed.is_empty() {
        return HitCounters::unavailable("no counters found in the kernel rule set");
    }

    let in_numbers: Vec<u32> = rules
        .iter()
        .filter(|r| r.direction == Direction::In && !r.is_route() && !r.v6)
        .map(|r| r.number)
        .collect();
    let out_numbers: Vec<u32> = rules
        .iter()
        .filter(|r| r.direction == Direction::Out && !r.is_route() && !r.v6)
        .map(|r| r.number)
        .collect();

    let mut per_rule = BTreeMap::new();
    let in_aligned = align(&parsed, INPUT_CHAIN, &in_numbers);
    let out_aligned = align(&parsed, OUTPUT_CHAIN, &out_numbers);
    let mut reliable = false;
    let mut notes = Vec::new();

    match &in_aligned {
        Some(map) => {
            per_rule.extend(map.clone());
            reliable = true;
        }
        None => notes.push(format!(
            "incoming rules did not line up with the kernel's {} chain",
            INPUT_CHAIN
        )),
    }
    if let Some(map) = &out_aligned {
        per_rule.extend(map.clone());
        reliable = true;
    }

    let note = if reliable {
        let mut text = "hits since the firewall was last reloaded".to_string();
        if !notes.is_empty() {
            text.push_str(&format!(" ({})", notes.join("; ")));
        }
        text
    } else if notes.is_empty() {
        "no rules to count yet".to_string()
    } else {
        notes.join("; ")
    };

    HitCounters {
        per_rule,
        chain_totals: vec![
            (INPUT_CHAIN.to_string(), chain_total(&parsed, INPUT_CHAIN)),
            (OUTPUT_CHAIN.to_string(), chain_total(&parsed, OUTPUT_CHAIN)),
        ],
        reliable,
        note,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::rule::{Endpoint, LogMode, Protocol};

    fn rule(number: u32, direction: Direction, v6: bool) -> Rule {
        Rule {
            number,
            action: crate::core::rule::Action::Allow,
            direction,
            interface_in: None,
            interface_out: None,
            protocol: Protocol::Tcp,
            from: Endpoint::any(),
            to: Endpoint::port(22),
            log: LogMode::None,
            comment: None,
            v6,
            route: false,
        }
    }

    fn fixture(packets: &[u64]) -> String {
        let mut objects = vec![r#"{"metainfo":{"version":"1.1.6"}}"#.to_string()];
        objects.push(r#"{"table":{"family":"ip","name":"filter","handle":1}}"#.to_string());
        for (index, count) in packets.iter().enumerate() {
            objects.push(format!(
                r#"{{"rule":{{"family":"ip","table":"filter","chain":"ufw-user-input","handle":{index},"expr":[{{"match":{{"op":"==","left":{{"payload":{{"protocol":"tcp","field":"dport"}}}},"right":22}}}},{{"counter":{{"packets":{count},"bytes":{},"per-packet":false}}}},{{"accept":null}}]}}}}"#,
                count * 60
            ));
        }
        format!(r#"{{"nftables":[{}]}}"#, objects.join(","))
    }

    #[test]
    fn parses_counters_out_of_nft_json() {
        let rules = parse_nft_rules(&fixture(&[10, 250]));
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].packets, Some(10));
        assert_eq!(rules[1].packets, Some(250));
        assert_eq!(rules[0].chain, INPUT_CHAIN);
    }

    #[test]
    fn aligns_by_position_when_the_lengths_match() {
        let parsed = parse_nft_rules(&fixture(&[7, 9]));
        let numbers = vec![1, 4];
        let map = align(&parsed, INPUT_CHAIN, &numbers).expect("should align");
        assert_eq!(map.get(&1), Some(&7));
        assert_eq!(map.get(&4), Some(&9));
    }

    #[test]
    fn refuses_to_align_when_a_limit_rule_expanded() {
        // Three kernel rules but only two ufw rules: a `limit` rule split itself in two.
        let parsed = parse_nft_rules(&fixture(&[7, 9, 11]));
        assert!(align(&parsed, INPUT_CHAIN, &[1, 2]).is_none());
    }

    #[test]
    fn chain_totals_are_useful_even_when_alignment_fails() {
        let parsed = parse_nft_rules(&fixture(&[7, 9, 11]));
        assert_eq!(chain_total(&parsed, INPUT_CHAIN), 27);
    }

    #[test]
    fn garbage_input_yields_no_rules() {
        assert!(parse_nft_rules("not json").is_empty());
        assert!(parse_nft_rules("{}").is_empty());
        assert!(parse_nft_rules(r#"{"nftables":[]}"#).is_empty());
    }

    #[test]
    fn collect_reports_unreliable_when_counts_disagree() {
        let rules = vec![rule(1, Direction::In, false)];
        let counters = collect(&fixture(&[1, 2]), &rules);
        assert!(!counters.reliable);
        assert!(counters.get(1).is_none());
        assert!(counters.note.contains("did not line up"));
    }

    #[test]
    fn collect_maps_numbers_when_counts_agree() {
        let rules = vec![rule(1, Direction::In, false), rule(2, Direction::In, false)];
        let counters = collect(&fixture(&[5, 6]), &rules);
        assert!(counters.reliable);
        assert_eq!(counters.get(1), Some(5));
        assert_eq!(counters.get(2), Some(6));
    }

    #[test]
    fn ipv6_rules_are_excluded_from_alignment() {
        // ufw prints the v4 and v6 variants as separate numbers, but only v4 lives in this chain.
        let rules = vec![rule(1, Direction::In, false), rule(2, Direction::In, true)];
        let counters = collect(&fixture(&[42]), &rules);
        assert!(counters.reliable);
        assert_eq!(counters.get(1), Some(42));
        assert!(counters.get(2).is_none());
    }

    #[test]
    fn unavailable_counters_carry_a_reason() {
        let counters = HitCounters::unavailable("no root");
        assert!(!counters.reliable);
        assert_eq!(counters.note, "no root");
        assert_eq!(counters.get(1), None);
    }
}
