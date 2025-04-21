use clap::ValueEnum;

/// Mode of appending to a file
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum AppendMode {
    /// Append to existing or do nothing
    Append,
    /// Append or create
    AppendCreate,
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

/// Mode of creation: 0 - create or do nothing if exists, 1 - create or rename existing and create new
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CreateDirMode {
    /// Create or do nothing
    CreateNew = 0,
    /// Create or rename existing and create
    RenameCreate,
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

/// Type of the file system link
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum LinkKind {
    /// Hard link
    H,
    /// Symbolic link
    S,
}
