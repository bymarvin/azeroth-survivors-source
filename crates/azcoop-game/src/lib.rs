//! Static facts about the supported game builds and typed readers over a
//! memory view. Pure: no Windows API and no process access, so everything here
//! is testable offline against the executables on disk and synthetic memory.

pub mod builds;
pub mod pe;
pub mod profile;
pub mod readers;

pub type Result<T> = std::result::Result<T, String>;
