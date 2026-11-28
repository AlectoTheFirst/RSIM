//! The rounds of the routing calculation over the protocols. Each round
//! computes the state from the state of the round before: OSPF, then BGP
//! over the route table of the round before, then the route table, then the
//! redistributions and the leaks. The run ends at the first round that
//! changes nothing. A state that repeats before that ends the run with the
//! cycle. The run has no round budget.

use std::collections::BTreeMap;

/// The result of the rounds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Rounds<S> {
    /// The state that the round `rounds` computes again.
    Converged { state: S, rounds: usize },
    /// The states of the cycle: the state of round `first` is the state of
    /// round `first + states.len()`.
    Cycle { first: usize, states: Vec<S> },
}

/// The rounds from `start`. `step` computes the state of the next round
/// from the state of a round and the number of that round, 0 for `start`.
pub fn run<S: Clone + Ord>(start: S, mut step: impl FnMut(&S, usize) -> S) -> Rounds<S> {
    let mut states = vec![start];
    let mut index: BTreeMap<S, usize> = BTreeMap::from([(states[0].clone(), 0)]);
    loop {
        let r = states.len() - 1;
        let next = step(&states[r], r);
        if next == states[r] {
            return Rounds::Converged {
                state: next,
                rounds: r + 1,
            };
        }
        if let Some(&first) = index.get(&next) {
            return Rounds::Cycle {
                first,
                states: states.split_off(first),
            };
        }
        index.insert(next.clone(), states.len());
        states.push(next);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_counter_that_stops_at_3_converges_and_a_flip_is_a_cycle_of_2() {
        assert_eq!(
            run(0u32, |s, _| (*s + 1).min(3)),
            Rounds::Converged {
                state: 3,
                rounds: 4
            }
        );
        assert_eq!(
            run(false, |s, _| !s),
            Rounds::Cycle {
                first: 0,
                states: vec![false, true]
            }
        );
        assert_eq!(
            run(0u32, |s, _| if *s < 2 { s + 1 } else { 1 }),
            Rounds::Cycle {
                first: 1,
                states: vec![1, 2]
            }
        );
    }
}
