use clap::ValueEnum;

use crate::serialise::DeserializationError;

/// Mode of appending to a file
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum AppendMode {
    /// Append to existing or do nothing
    Append,
    /// Append or create
    AppendCreate,
}

impl TryFrom<u8> for AppendMode {
    type Error = DeserializationError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Append),
            1 => Ok(Self::AppendCreate),
            _ => Err(DeserializationError::UnknownEnumValue),
        }
    }
}

/// Mode of deletion
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum DeleteMode {
    /// Delete only if path is file
    File = 0,
    /// Delete only if path is empty directory
    EmptyDir,
    /// Path is a file or empty directory
    FileDir,
    /// Recursively delete directory
    Dir,
    /// Link
    Link,
    /// Any file system object, recursive for directories. If the object is a link,
    /// remove the link, not the object it points to
    Any,
}

impl TryFrom<u8> for DeleteMode {
    type Error = DeserializationError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::File),
            1 => Ok(Self::EmptyDir),
            2 => Ok(Self::FileDir),
            3 => Ok(Self::Dir),
            4 => Ok(Self::Link),
            5 => Ok(Self::Any),
            _ => Err(DeserializationError::UnknownEnumValue),
        }
    }
}

/// Mode of file creation when sending
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CreateFileMode {
    /// Create or overwrite
    Overwrite = 0,
    /// Create or do nothing
    CreateNew,
    /// Create or rename existing and create
    RenameCreate,
}

impl TryFrom<u8> for CreateFileMode {
    type Error = DeserializationError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Overwrite),
            1 => Ok(Self::CreateNew),
            2 => Ok(Self::RenameCreate),
            _ => Err(DeserializationError::UnknownEnumValue),
        }
    }
}

/// Mode of creation: 0 - create or do nothing if exists, 1 - create or rename existing and create new
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CreateDirMode {
    /// Create or do nothing
    CreateNew = 0,
    /// Create or rename existing and create
    RenameCreate,
}

impl TryFrom<u8> for CreateDirMode {
    type Error = DeserializationError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::CreateNew),
            1 => Ok(Self::RenameCreate),
            _ => Err(DeserializationError::UnknownEnumValue),
        }
    }
}

/// Mode of link creation
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CreateLinkMode {
    /// Create or overwrite
    Overwrite = 0,
    /// Create or do nothing
    CreateNew,
    /// Create or rename and create
    RenameCreate,
}

impl TryFrom<u8> for CreateLinkMode {
    type Error = DeserializationError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Overwrite),
            1 => Ok(Self::CreateNew),
            2 => Ok(Self::RenameCreate),
            _ => Err(DeserializationError::UnknownEnumValue),
        }
    }
}

/// Type of the file system link
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum LinkKind {
    /// Hard link
    H,
    /// Symbolic link
    S,
}

impl TryFrom<u8> for LinkKind {
    type Error = DeserializationError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::H),
            1 => Ok(Self::S),
            _ => Err(DeserializationError::UnknownEnumValue),
        }
    }
}
