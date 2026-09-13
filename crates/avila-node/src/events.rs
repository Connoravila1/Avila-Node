use std::collections::VecDeque;
use std::num::NonZeroUsize;

use serde::Serialize;
use thiserror::Error;

/// Fixed-size events keep retention bounded in bytes as well as entry count.
/// Future events carrying data must add payload limits and redaction tests.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeEvent {
    ConfigurationLoaded,
    StartupBlocked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct EventRecord {
    pub sequence: u64,
    pub event: NodeEvent,
}

/// Process-local diagnostic history, NOT a durable consensus journal.
#[derive(Debug)]
pub struct EventJournal {
    capacity: NonZeroUsize,
    next_sequence: u64,
    entries: VecDeque<EventRecord>,
}

impl EventJournal {
    pub fn new(capacity: NonZeroUsize) -> Self {
        Self {
            capacity,
            next_sequence: 0,
            entries: VecDeque::new(),
        }
    }

    pub fn push(&mut self, event: NodeEvent) -> Result<(), JournalError> {
        let sequence = self.next_sequence;
        let next_sequence = sequence
            .checked_add(1)
            .ok_or(JournalError::SequenceExhausted)?;
        if self.entries.len() == self.capacity.get() {
            self.entries.pop_front();
        }
        self.entries.push_back(EventRecord { sequence, event });
        self.next_sequence = next_sequence;
        Ok(())
    }

    pub fn entries(&self) -> impl DoubleEndedIterator<Item = &EventRecord> {
        self.entries.iter()
    }
}

#[derive(Debug, Error)]
pub enum JournalError {
    #[error("event sequence exhausted; refusing to reuse an event identifier")]
    SequenceExhausted,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn retains_only_the_newest_entries_in_order() {
        let mut journal = EventJournal::new(NonZeroUsize::new(2).unwrap());
        for _ in 0..5 {
            journal.push(NodeEvent::ConfigurationLoaded).unwrap();
        }
        let sequences: Vec<_> = journal.entries().map(|entry| entry.sequence).collect();
        assert_eq!(sequences, vec![3, 4]);
    }

    #[test]
    fn single_entry_capacity_is_supported() {
        let mut journal = EventJournal::new(NonZeroUsize::MIN);
        journal.push(NodeEvent::ConfigurationLoaded).unwrap();
        journal.push(NodeEvent::StartupBlocked).unwrap();
        assert_eq!(journal.entries().count(), 1);
        assert_eq!(
            journal.entries().next().unwrap().event,
            NodeEvent::StartupBlocked
        );
    }

    #[test]
    fn sequence_exhaustion_does_not_mutate_history() {
        let mut journal = EventJournal::new(NonZeroUsize::MIN);
        journal.push(NodeEvent::ConfigurationLoaded).unwrap();
        journal.next_sequence = u64::MAX;
        assert!(journal.push(NodeEvent::StartupBlocked).is_err());
        assert_eq!(journal.entries().next().unwrap().sequence, 0);
    }
}
