use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("config: {0}")]
    Config(String),

    #[error("plugin `{tag}` ({kind}): {message}")]
    Plugin {
        tag: String,
        kind: String,
        message: String,
    },

    #[error("unknown plugin tag `{0}`")]
    UnknownTag(String),

    #[error("dns protocol: {0}")]
    Protocol(String),

    #[error("upstream {addr}: {message}")]
    Upstream { addr: String, message: String },

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn config(msg: impl Into<String>) -> Self {
        Self::Config(msg.into())
    }

    pub fn plugin(tag: impl Into<String>, kind: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Plugin {
            tag: tag.into(),
            kind: kind.into(),
            message: message.into(),
        }
    }

    pub fn protocol(msg: impl Into<String>) -> Self {
        Self::Protocol(msg.into())
    }
}
