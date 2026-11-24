//! Exact zero-polling deadline scheduler across all timed `node.sqlite` subsystems:
//! `events`/`batches`, `messages`, `transfers`, and `kv_entries`.

use crate::db::NodeDb;
use crate::error::StoreResult;
use crate::events::EventTickReport;
use crate::messages::MessageTickReport;
use crate::transfers::TransferTickReport;

/// Per-subsystem breakdown of the next scheduled wake timestamp (epoch ms).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeadlineBreakdown {
    pub events: Option<i64>,
    pub messages: Option<i64>,
    pub transfers: Option<i64>,
    pub kv: Option<i64>,
    pub earliest: Option<i64>,
}

/// Combined housekeeping report returned by [`NodeDb::tick`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TickReport {
    pub events: EventTickReport,
    pub messages: MessageTickReport,
    pub transfers: TransferTickReport,
    pub kv_expired: usize,
}

impl NodeDb {
    /// Computes the exact earliest wake timestamp (epoch ms) across `events`/`batches`,
    /// `messages`, `transfers`, and `kv_entries`.
    ///
    /// Returns `None` when the node is completely idle (zero polling!).
    pub fn next_deadline_ms(&self, now_ms: i64) -> StoreResult<Option<i64>> {
        Ok(self.next_deadline_breakdown(now_ms)?.earliest)
    }

    /// Computes per-subsystem deadlines alongside the overall earliest wake timestamp.
    pub fn next_deadline_breakdown(&self, now_ms: i64) -> StoreResult<DeadlineBreakdown> {
        let events = self.events().next_deadline_ms(now_ms)?;
        let messages = self.messages().next_deadline_ms(now_ms)?;
        let transfers = self.transfers().next_deadline_ms(now_ms)?;
        let kv = self.kv().next_deadline_ms()?;

        let earliest = [events, messages, transfers, kv].into_iter().flatten().min();
        Ok(DeadlineBreakdown {
            events,
            messages,
            transfers,
            kv,
            earliest,
        })
    }

    /// Runs one deterministic housekeeping tick across all four timed subsystems.
    pub fn tick(&self, now_ms: i64) -> StoreResult<TickReport> {
        let events = self.events().tick(now_ms)?;
        let messages = self.messages().tick(now_ms)?;
        let transfers = self.transfers().tick(now_ms)?;
        let kv_expired = self.kv().tick(now_ms)?;
        Ok(TickReport {
            events,
            messages,
            transfers,
            kv_expired,
        })
    }
}
