pub mod auth;
pub mod crypto;
pub mod http;
pub mod config;
pub mod error;
pub mod status;
pub mod wrap;
pub mod unwrap;
pub mod digest;
pub mod keyid;

pub use auth::*;
pub use crypto::*;
pub use self::http::*;
pub use config::*;
pub use error::*;
pub use status::*;
pub use wrap::*;
pub use unwrap::*;
pub use digest::*;
pub use keyid::*;

// "KID" + two byte version number (v1)
pub const VERSION_1_HEADER: &'static [u8] = b"\x4b\x49\x44\x00\x01";

