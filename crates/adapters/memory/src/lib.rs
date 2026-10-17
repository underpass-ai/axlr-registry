//! In-memory adapters of every port, for unit and use-case tests. One
//! adapter per file.

mod fixed_clock;
mod memory_artifacts;
mod memory_audit;
mod memory_idempotency;
mod memory_index;
mod memory_principals;
mod memory_publishers;
mod memory_tools;
mod recording_index_trigger;
mod recording_scheduler;

pub use fixed_clock::FixedClock;
pub use memory_artifacts::MemoryArtifacts;
pub use memory_audit::MemoryAudit;
pub use memory_idempotency::MemoryIdempotency;
pub use memory_index::MemoryIndex;
pub use memory_principals::MemoryPrincipals;
pub use memory_publishers::MemoryPublishers;
pub use memory_tools::MemoryTools;
pub use recording_index_trigger::RecordingIndexTrigger;
pub use recording_scheduler::RecordingScheduler;
