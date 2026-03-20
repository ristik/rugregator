pub mod disk;
pub mod mem;
pub mod traits;

pub use disk::{DiskSmt, DiskSmtSnapshot};
pub use mem::{MemSmt, MemSmtSnapshot, PersistMode};
pub use traits::{SmtStore, SmtStoreSnapshot};
