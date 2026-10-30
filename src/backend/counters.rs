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

/**
 * Packet counters for the firewall, as shown in the rules table.
 *
 * The numbers come from the kernel via `nft`, and are only trusted when the
 * kernel rules line up exactly with the ufw rules. When they do not, the set is
 * marked unreliable and carries a note explaining why, because wrong numbers
 * would be worse than none.
 *
 * # Fields
 *
 * * `per_rule` (`BTreeMap<u32, u64>`) - Packets matched per ufw rule number.
 * * `chain_totals` (`Vec<(String, u64)>`) - Total packets per ufw chain, useful even when per-rule alignment fails.
 * * `reliable` (`bool`) - `false` means `per_rule` is empty on purpose.
 * * `note` (`String`) - Why the numbers are missing or approximate, shown in the UI.
 */
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
    /**
     * Builds a counter set that deliberately carries no numbers.
     *
     * This is the "we could not read the kernel counters" value: `per_rule` and
     * `chain_totals` are empty and `reliable` is `false`, so the UI shows the
     * note instead of misleading zeros.
     *
     * # Arguments
     *
     * * `note` (`impl Into<String>`) - Human-readable reason the counters are
     *   missing, stored verbatim in [`HitCounters::note`].
     *
     * # Returns
     *
     * `HitCounters` - An empty, unreliable counter set carrying `note`.
     */
    pub fn unavailable(note: impl Into<String>) -> Self {
        Self {
            per_rule: BTreeMap::new(),
            chain_totals: Vec::new(),
            reliable: false,
            note: note.into(),
        }
    }

    /**
     * Looks up the packet count recorded for one ufw rule number.
     *
     * # Arguments
     *
     * * `self` (`&HitCounters`) - The counter set being read; it is not modified.
     * * `number` (`u32`) - The ufw rule number to look up.
     *
     * # Returns
     *
     * `Option<u64>` - The packet count, or `None` when that rule has no
     * aligned counter (for example when alignment failed or the rule is IPv6).
     */
    pub fn get(&self, number: u32) -> Option<u64> {
        self.per_rule.get(&number).copied()
    }

    /**
     * Looks up the total packet count recorded for one ufw chain.
     *
     * # Arguments
     *
     * * `self` (`&HitCounters`) - The counter set being read; it is not modified.
     * * `chain` (`&str`) - Chain name to find, e.g. `ufw-user-input`.
     *
     * # Returns
     *
     * `Option<u64>` - The summed packet count for that chain, or `None` when the
     * chain was not recorded.
     */
    pub fn chain_total(&self, chain: &str) -> Option<u64> {
        self.chain_totals
            .iter()
            .find(|(name, _)| name == chain)
            .map(|(_, total)| *total)
    }
}

/**
 * One kernel rule as extracted from `nft -j list ruleset`.
 *
 * Only the chain name and the packet counter are kept, because that is all the
 * alignment logic needs.
 *
 * # Fields
 *
 * * `chain` (`String`) - Name of the nft chain the rule belongs to.
 * * `packets` (`Option<u64>`) - Packet count, or `None` when the rule has no counter expression.
 */
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NftRule {
    pub chain: String,
    pub packets: Option<u64>,
}

/**
 * Extracts every rule in the nft JSON that carries a packet counter.
 *
 * Objects without a `rule`, without a `chain`, or with malformed JSON are
 * skipped rather than reported, so a partial ruleset still yields what it can.
 *
 * # Arguments
 *
 * * `json` (`&str`) - The raw output of `nft -j list ruleset`.
 *
 * # Returns
 *
 * `Vec<NftRule>` - One entry per rule found, in document order; empty when the
 * JSON is invalid or has no `nftables` array.
 */
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

/**
 * Sums the counters of one chain.
 *
 * Rules without a counter contribute nothing, so the total is a lower bound
 * when some rules are uncounted.
 *
 * # Arguments
 *
 * * `rules` (`&[NftRule]`) - The parsed kernel rules to scan.
 * * `chain` (`&str`) - Chain name to total, e.g. `ufw-user-input`.
 *
 * # Returns
 *
 * `u64` - The sum of the packet counts of every matching rule, or `0` when the
 * chain has no counted rules.
 */
pub fn chain_total(rules: &[NftRule], chain: &str) -> u64 {
    rules
        .iter()
        .filter(|r| r.chain == chain)
        .filter_map(|r| r.packets)
        .sum()
}

/**
 * Maps chain position to ufw rule numbers, or `None` when the lengths disagree.
 *
 * Alignment is positional because ufw appends rules to the chain in order. A
 * `limit` rule or an application profile expands into several kernel rules, so
 * a length mismatch means the mapping cannot be trusted and is refused.
 *
 * # Arguments
 *
 * * `rules` (`&[NftRule]`) - The parsed kernel rules to scan.
 * * `chain` (`&str`) - Chain whose rules are aligned, e.g. `ufw-user-input`.
 * * `numbers` (`&[u32]`) - The ufw rule numbers expected in that chain, in order.
 *
 * # Returns
 *
 * `Option<BTreeMap<u32, u64>>` - Rule number to packet count, or `None` when the
 * counts differ or `numbers` is empty. Rules without a counter map to `0`.
 */
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

/**
 * Full parse used by the backend: read the nft JSON and map it onto the rules we
 * know about.
 *
 * Incoming and outgoing rules are aligned separately against
 * `ufw-user-input` and `ufw-user-output`; IPv6 twins and route rules are
 * excluded because they do not live in those chains. Chain totals are always
 * reported, even when per-rule alignment fails.
 *
 * # Arguments
 *
 * * `json` (`&str`) - The raw output of `nft -j list ruleset`.
 * * `rules` (`&[Rule]`) - The ufw rules the counters should be mapped onto.
 *
 * # Returns
 *
 * `HitCounters` - The aligned per-rule counts plus chain totals, marked
 * unreliable with an explanatory note when alignment was not possible.
 */
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

    /**
     * Builds a minimal allow rule for the alignment tests.
     *
     * # Arguments
     *
     * * `number` (`u32`) - The ufw rule number to assign.
     * * `direction` (`Direction`) - Traffic direction of the rule.
     * * `v6` (`bool`) - Whether the rule is the IPv6 twin of a v4 rule.
     *
     * # Returns
     *
     * `Rule` - An allow rule to port 22/tcp from anywhere.
     */
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

    /**
     * Builds an `nft -j list ruleset` document with one input rule per count.
     *
     * # Arguments
     *
     * * `packets` (`&[u64]`) - Packet counts to emit, one rule each, in order.
     *
     * # Returns
     *
     * `String` - JSON text shaped like real nft output.
     */
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
    /**
     * Verifies that counters are read out of nft JSON in document order.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * `()` - This function returns no value; it asserts and panics on failure.
     */
    fn parses_counters_out_of_nft_json() {
        let rules = parse_nft_rules(&fixture(&[10, 250]));
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].packets, Some(10));
        assert_eq!(rules[1].packets, Some(250));
        assert_eq!(rules[0].chain, INPUT_CHAIN);
    }

    #[test]
    /**
     * Verifies that equal-length chains are mapped onto ufw rule numbers.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * `()` - This function returns no value; it asserts and panics on failure.
     */
    fn aligns_by_position_when_the_lengths_match() {
        let parsed = parse_nft_rules(&fixture(&[7, 9]));
        let numbers = vec![1, 4];
        let map = align(&parsed, INPUT_CHAIN, &numbers).expect("should align");
        assert_eq!(map.get(&1), Some(&7));
        assert_eq!(map.get(&4), Some(&9));
    }

    #[test]
    /**
     * Verifies that alignment is refused when a `limit` rule expanded into
     * several kernel rules.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * `()` - This function returns no value; it asserts and panics on failure.
     */
    fn refuses_to_align_when_a_limit_rule_expanded() {
        // Three kernel rules but only two ufw rules: a `limit` rule split itself in two.
        let parsed = parse_nft_rules(&fixture(&[7, 9, 11]));
        assert!(align(&parsed, INPUT_CHAIN, &[1, 2]).is_none());
    }

    #[test]
    /**
     * Verifies that chain totals stay useful even when per-rule alignment fails.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * `()` - This function returns no value; it asserts and panics on failure.
     */
    fn chain_totals_are_useful_even_when_alignment_fails() {
        let parsed = parse_nft_rules(&fixture(&[7, 9, 11]));
        assert_eq!(chain_total(&parsed, INPUT_CHAIN), 27);
    }

    #[test]
    /**
     * Verifies that malformed or empty nft JSON yields no rules instead of an
     * error.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * `()` - This function returns no value; it asserts and panics on failure.
     */
    fn garbage_input_yields_no_rules() {
        assert!(parse_nft_rules("not json").is_empty());
        assert!(parse_nft_rules("{}").is_empty());
        assert!(parse_nft_rules(r#"{"nftables":[]}"#).is_empty());
    }

    #[test]
    /**
     * Verifies that mismatched counts are reported as unreliable with a note.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * `()` - This function returns no value; it asserts and panics on failure.
     */
    fn collect_reports_unreliable_when_counts_disagree() {
        let rules = vec![rule(1, Direction::In, false)];
        let counters = collect(&fixture(&[1, 2]), &rules);
        assert!(!counters.reliable);
        assert!(counters.get(1).is_none());
        assert!(counters.note.contains("did not line up"));
    }

    #[test]
    /**
     * Verifies that matching counts are mapped onto the expected rule numbers.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * `()` - This function returns no value; it asserts and panics on failure.
     */
    fn collect_maps_numbers_when_counts_agree() {
        let rules = vec![rule(1, Direction::In, false), rule(2, Direction::In, false)];
        let counters = collect(&fixture(&[5, 6]), &rules);
        assert!(counters.reliable);
        assert_eq!(counters.get(1), Some(5));
        assert_eq!(counters.get(2), Some(6));
    }

    #[test]
    /**
     * Verifies that IPv6 rules are excluded from alignment because only the v4
     * variant lives in the counted chain.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * `()` - This function returns no value; it asserts and panics on failure.
     */
    fn ipv6_rules_are_excluded_from_alignment() {
        // ufw prints the v4 and v6 variants as separate numbers, but only v4 lives in this chain.
        let rules = vec![rule(1, Direction::In, false), rule(2, Direction::In, true)];
        let counters = collect(&fixture(&[42]), &rules);
        assert!(counters.reliable);
        assert_eq!(counters.get(1), Some(42));
        assert!(counters.get(2).is_none());
    }

    #[test]
    /**
     * Verifies that [`HitCounters::unavailable`] keeps its reason and reports no
     * numbers.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * `()` - This function returns no value; it asserts and panics on failure.
     */
    fn unavailable_counters_carry_a_reason() {
        let counters = HitCounters::unavailable("no root");
        assert!(!counters.reliable);
        assert_eq!(counters.note, "no root");
        assert_eq!(counters.get(1), None);
    }
}
