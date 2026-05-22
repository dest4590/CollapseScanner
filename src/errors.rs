use std::fmt;
use std::io;

#[derive(Debug)]
pub enum ScanError {
    IoError(io::Error),
    ZipError(zip::result::ZipError),
    ClassParseError { path: String, msg: String },
    UnsupportedFileType(Option<std::ffi::OsString>),
    JsonError(serde_json::Error),
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScanError::IoError(e) => write!(f, "IO error: {}", e),
            ScanError::ZipError(e) => write!(f, "Zip error: {}", e),
            ScanError::ClassParseError { path, msg } => {
                write!(f, "Class parse error in '{}': {}", path, msg)
            }
            ScanError::UnsupportedFileType(ext) => {
                write!(f, "Unsupported file type: {:?}", ext)
            }
            ScanError::JsonError(e) => write!(f, "JSON error: {}", e),
        }
    }
}

impl std::error::Error for ScanError {}

impl From<io::Error> for ScanError {
    fn from(e: io::Error) -> Self {
        ScanError::IoError(e)
    }
}

impl From<zip::result::ZipError> for ScanError {
    fn from(e: zip::result::ZipError) -> Self {
        ScanError::ZipError(e)
    }
}

impl From<serde_json::Error> for ScanError {
    fn from(e: serde_json::Error) -> Self {
        ScanError::JsonError(e)
    }
}
