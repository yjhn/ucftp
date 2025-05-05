use std::{
    env,
    ffi::CString,
    fs,
    io::{self, Write},
    os,
    path::{Path, PathBuf},
    process,
    str::FromStr,
};

use log::warn;
use ucftp_shared::{
    message::*,
    serialise::{DeserializationError, TryBufDeserialize, u64_from_le_bytes},
};

pub struct FileData {
    data: Box<[u8]>,
}
impl FileData {
    fn new(data: Box<[u8]>) -> Self {
        Self { data }
    }

    fn data(&self) -> &[u8] {
        &self.data
    }
}

impl std::fmt::Debug for FileData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileData")
            .field("data", &format!("<file data of len: {}>", self.data.len()))
            .finish()
    }
}

// TODO(future): make every string or byte array inside message point to places
// in buf using `ouroboros` or `yoke` crate
#[derive(Debug)]
pub enum Command {
    Execute {
        absolute_path: Box<str>,
        env_vars: Box<[(Box<str>, Box<str>)]>,
        program_args: Box<[Box<str>]>,
    },
    ExecuteInShell {
        command: Box<str>,
    },
    SetEnvVars {
        env_vars: Box<[(Box<str>, Box<str>)]>,
    },
    RemEnvVars {
        env_vars: Box<[Box<str>]>,
    },
    ExecuteReceived {
        transfer_session_id: u64,
        env_vars: Box<[(Box<str>, Box<str>)]>,
        program_args: Box<[Box<str>]>,
    },
    CreateDir {
        absolute_path: Box<str>,
        mode: CreateDirMode,
    },
    CreateFile {
        absolute_path: Box<str>,
        mode: CreateFileMode,
        file_data: FileData,
    },
    AppendToFile {
        absolute_path: Box<str>,
        mode: AppendMode,
        file_data: FileData,
    },
    AppendToFileFromTransfer {
        transfer_session_id: u64,
        file_data: FileData,
    },
    RenameItem {
        absolute_path: Box<str>,
        new_name: Box<str>,
    },
    MoveItem {
        absolute_path: Box<str>,
        new_absolute_path: Box<str>,
    },
    CreateLink {
        absolute_path_src: Box<str>,
        absolute_path_dst: Box<str>,
        mode: CreateLinkMode,
        kind: LinkKind,
    },
    Delete {
        absolute_path: Box<str>,
        mode: DeleteMode,
    },
}

impl Command {
    fn try_from_buf(buf: &[u8]) -> Result<(usize, Command), DeserializationError> {
        let mut buf_used = 1;
        match buf[0] {
            // Execute command
            0 => {
                let (used, absolute_path) = Box::try_deserialize_from_buf(&buf[buf_used..])?;
                buf_used += used;
                let (used, env_vars) = Box::try_deserialize_from_buf(&buf[buf_used..])?;
                buf_used += used;
                let (used, program_args) = Box::try_deserialize_from_buf(&buf[buf_used..])?;
                buf_used += used;
                Ok((
                    buf_used,
                    Command::Execute {
                        absolute_path,
                        env_vars,
                        program_args,
                    },
                ))
            }
            // Exec in default shell (we can do so using libc::system)
            1 => {
                let (used, command) = Box::try_deserialize_from_buf(&buf[buf_used..])?;
                buf_used += used;
                Ok((buf_used, Command::ExecuteInShell { command }))
            }
            // Set env vars
            2 => {
                let (used, env_vars) = Box::try_deserialize_from_buf(&buf[buf_used..])?;
                buf_used += used;
                Ok((buf_used, Command::SetEnvVars { env_vars }))
            }
            // Remove env vars
            3 => {
                let (used, env_vars) = Box::try_deserialize_from_buf(&buf[buf_used..])?;
                buf_used += used;
                Ok((buf_used, Command::RemEnvVars { env_vars }))
            }
            // Execute received file
            4 => {
                if buf.len() - buf_used < 8 {
                    return Err(DeserializationError::IncompleteValue);
                }
                let transfer_session_id = u64_from_le_bytes(&buf[buf_used..]);
                buf_used += 8;
                let (used, env_vars) = Box::try_deserialize_from_buf(&buf[buf_used..])?;
                buf_used += used;
                let (used, program_args) = Box::try_deserialize_from_buf(&buf[buf_used..])?;
                buf_used += used;
                Ok((
                    buf_used,
                    Command::ExecuteReceived {
                        transfer_session_id,
                        env_vars,
                        program_args,
                    },
                ))
            }
            // Create dir
            5 => {
                let (used, absolute_path) = Box::try_deserialize_from_buf(&buf[buf_used..])?;
                buf_used += used;
                if buf.len() == buf_used {
                    return Err(DeserializationError::ValueExpected);
                }
                let mode = CreateDirMode::try_from(buf[buf_used])?;
                buf_used += 1;
                Ok((
                    buf_used,
                    Command::CreateDir {
                        absolute_path,
                        mode,
                    },
                ))
            }
            // Create file
            6 => {
                let (used, absolute_path) = Box::try_deserialize_from_buf(&buf[buf_used..])?;
                buf_used += used;
                if buf.len() == buf_used {
                    return Err(DeserializationError::ValueExpected);
                }
                let mode = CreateFileMode::try_from(buf[buf_used])?;
                buf_used += 1;
                let (used, file_data) = Box::try_deserialize_from_buf(&buf[buf_used..])?;
                buf_used += used;
                Ok((
                    buf_used,
                    Command::CreateFile {
                        absolute_path,
                        mode,
                        file_data: FileData::new(file_data),
                    },
                ))
            }
            // Append to file
            7 => {
                let (used, absolute_path) = Box::try_deserialize_from_buf(&buf[buf_used..])?;
                buf_used += used;
                if buf.len() == buf_used {
                    return Err(DeserializationError::ValueExpected);
                }
                let mode = AppendMode::try_from(buf[buf_used])?;
                buf_used += 1;
                let (used, file_data) = Box::try_deserialize_from_buf(&buf[buf_used..])?;
                buf_used += used;
                Ok((
                    buf_used,
                    Command::AppendToFile {
                        absolute_path,
                        mode,
                        file_data: FileData::new(file_data),
                    },
                ))
            }
            // Append to file from transfer
            8 => {
                if buf.len() - buf_used < 8 {
                    return Err(DeserializationError::IncompleteValue);
                }
                let transfer_session_id = u64_from_le_bytes(&buf[buf_used..]);
                buf_used += 8;
                let (used, file_data) = Box::try_deserialize_from_buf(&buf[buf_used..])?;
                buf_used += used;
                Ok((
                    buf_used,
                    Command::AppendToFileFromTransfer {
                        transfer_session_id,
                        file_data: FileData::new(file_data),
                    },
                ))
            }
            // Rename item
            9 => {
                let (used, absolute_path) = Box::try_deserialize_from_buf(&buf[buf_used..])?;
                buf_used += used;
                let (used, new_name) = Box::try_deserialize_from_buf(&buf[buf_used..])?;
                buf_used += used;
                Ok((
                    buf_used,
                    Command::RenameItem {
                        absolute_path,
                        new_name,
                    },
                ))
            }
            // Move item
            10 => {
                let (used, absolute_path) = Box::try_deserialize_from_buf(&buf[buf_used..])?;
                buf_used += used;
                let (used, new_absolute_path) = Box::try_deserialize_from_buf(&buf[buf_used..])?;
                buf_used += used;
                Ok((
                    buf_used,
                    Command::MoveItem {
                        absolute_path,
                        new_absolute_path,
                    },
                ))
            }
            // Add fs link
            11 => {
                let (used, absolute_path_src) = Box::try_deserialize_from_buf(&buf[buf_used..])?;
                buf_used += used;
                let (used, absolute_path_dst) = Box::try_deserialize_from_buf(&buf[buf_used..])?;
                buf_used += used;
                if buf.len() == buf_used {
                    return Err(DeserializationError::ValueExpected);
                }
                let mode = CreateLinkMode::try_from(buf[buf_used] & 0xf0)?;
                let kind = LinkKind::try_from(buf[buf_used] & 0x0f)?;
                buf_used += 1;
                Ok((
                    buf_used,
                    Command::CreateLink {
                        absolute_path_src,
                        absolute_path_dst,
                        mode,
                        kind,
                    },
                ))
            }
            // Delete item
            12 => {
                let (used, absolute_path) = Box::try_deserialize_from_buf(&buf[buf_used..])?;
                buf_used += used;
                if buf.len() == buf_used {
                    return Err(DeserializationError::ValueExpected);
                }
                let mode = DeleteMode::try_from(buf[buf_used])?;
                buf_used += used;
                Ok((
                    buf_used,
                    Command::Delete {
                        absolute_path,
                        mode,
                    },
                ))
            }
            _ => Err(DeserializationError::UnknownType),
        }
    }

    fn find_new_name(path: &str) -> String {
        // Try names to find the first one that does not exist
        let mut p = path.to_string();
        let mut s: u32 = 1;
        loop {
            let len = p.len();
            p.push_str(&format!("-{s}"));
            if Path::new(&p).exists() {
                p.truncate(len);
                s += 1;
            } else {
                return p;
            }
        }
    }

    /// Ok(true) = command execution successful. In the case of program execution,
    ///            successful means that the executable was run (i.e. it existed
    ///            and had the needed permissions). Notably, the return value of the
    ///            executable is not taken into account.
    /// Ok(false) = command execution unsuccessful
    // TODO: we need to take ownership of strings inside self. Two options:
    // - take &mut self and use mem::take() for the strings
    // - take self and move out
    fn execute(self, executed_commands: &[CompactCommandSession]) -> CommandExecutionResult {
        match self {
            Command::Execute {
                absolute_path,
                env_vars,
                program_args,
            } => {
                match process::Command::new(absolute_path.as_ref())
                    .args(program_args.iter().map(|s| s.as_ref()))
                    .envs(env_vars.iter().map(|(k, v)| (k.as_ref(), v.as_ref())))
                    .spawn()
                {
                    Ok(p) => CommandExecutionResult::Process(p),
                    Err(e) => CommandExecutionResult::Error(e),
                }
            }
            Command::ExecuteInShell { command } => match c_system(&command) {
                Ok(_) => CommandExecutionResult::Success,
                Err(e) => CommandExecutionResult::Error(e),
            },
            Command::SetEnvVars { env_vars } => {
                for (k, v) in env_vars.iter() {
                    // SAFETY: safe if the current program is single-threaded or
                    // is Rust-only (Rust std uses a lock). Threads share the
                    // environment, while child processes do not (they get a copy).
                    // From docs it appears that Command::spawn() creates a child
                    // process, so changing the environment is safe in regards to
                    // them.
                    unsafe { env::set_var(k.as_ref(), v.as_ref()) }
                }
                CommandExecutionResult::Success
            }
            Command::RemEnvVars { env_vars } => {
                for k in env_vars.iter() {
                    // SAFETY: same as set_var
                    unsafe { env::remove_var(k.as_ref()) }
                }
                CommandExecutionResult::Success
            }
            Command::ExecuteReceived {
                transfer_session_id,
                env_vars,
                program_args,
            } => {
                if let Some(c) = executed_commands
                    .iter()
                    .find(|e| e.session_id == transfer_session_id)
                {
                    match process::Command::new(c.path.as_ref())
                        .args(program_args.iter().map(|s| s.as_ref()))
                        .envs(env_vars.iter().map(|(k, v)| (k.as_ref(), v.as_ref())))
                        .spawn()
                    {
                        Ok(p) => CommandExecutionResult::Process(p),
                        Err(e) => CommandExecutionResult::Error(e),
                    }
                } else {
                    CommandExecutionResult::SessionNotFound(transfer_session_id)
                }
            }
            Command::CreateDir {
                absolute_path,
                mode,
            } => {
                if Path::new(absolute_path.as_ref()).exists() {
                    match mode {
                        CreateDirMode::CreateNew => CommandExecutionResult::SuccessNoOp,
                        CreateDirMode::RenameCreate => {
                            let p = Self::find_new_name(&absolute_path);

                            match fs::create_dir(p) {
                                Ok(_) => CommandExecutionResult::Success,
                                Err(e) => CommandExecutionResult::Error(e),
                            }
                        }
                    }
                } else {
                    match fs::create_dir(absolute_path.as_ref()) {
                        Ok(_) => CommandExecutionResult::Success,
                        Err(e) => CommandExecutionResult::Error(e),
                    }
                }
            }
            Command::CreateFile {
                absolute_path,
                mode,
                file_data,
            } => {
                if Path::new(absolute_path.as_ref()).exists() {
                    match mode {
                        CreateFileMode::CreateNew => CommandExecutionResult::SuccessNoOp,
                        CreateFileMode::RenameCreate => {
                            let p = Self::find_new_name(&absolute_path);

                            match fs::create_dir(&p) {
                                Ok(_) => CommandExecutionResult::SuccessPath(p.into()),
                                Err(e) => CommandExecutionResult::Error(e),
                            }
                        }
                        CreateFileMode::Overwrite => {
                            match fs::write(absolute_path.as_ref(), &file_data.data()) {
                                Ok(_) => CommandExecutionResult::SuccessPath(absolute_path),
                                Err(e) => CommandExecutionResult::Error(e),
                            }
                        }
                    }
                } else {
                    match fs::write(absolute_path.as_ref(), file_data.data()) {
                        Ok(_) => CommandExecutionResult::SuccessPath(absolute_path),
                        Err(e) => CommandExecutionResult::Error(e),
                    }
                }
            }
            Command::AppendToFile {
                absolute_path,
                mode,
                file_data,
            } => {
                match fs::OpenOptions::new()
                    .append(true)
                    .create(mode == AppendMode::AppendCreate)
                    .open(absolute_path.as_ref())
                {
                    Ok(mut f) => match f.write_all(file_data.data()) {
                        Ok(_) => CommandExecutionResult::SuccessPath(absolute_path),
                        Err(e) => CommandExecutionResult::Error(e),
                    },
                    Err(e) => CommandExecutionResult::Error(e),
                }
            }
            Command::AppendToFileFromTransfer {
                transfer_session_id,
                file_data,
            } => {
                if let Some(c) = executed_commands
                    .iter()
                    .find(|e| e.session_id == transfer_session_id)
                {
                    match fs::OpenOptions::new()
                        .append(true)
                        .create(false)
                        .open(c.path.as_ref())
                    {
                        Ok(mut f) => match f.write_all(file_data.data()) {
                            Ok(_) => CommandExecutionResult::SuccessPath(c.path.clone()),
                            Err(e) => CommandExecutionResult::Error(e),
                        },
                        Err(e) => CommandExecutionResult::Error(e),
                    }
                } else {
                    CommandExecutionResult::SessionNotFound(transfer_session_id)
                }
            }
            Command::RenameItem {
                absolute_path,
                new_name,
            } => {
                let mut to: PathBuf = absolute_path.to_string().into();
                to.pop();
                to.push(new_name.as_ref());
                match fs::rename(absolute_path.as_ref(), to) {
                    Ok(_) => CommandExecutionResult::Success,
                    Err(e) => CommandExecutionResult::Error(e),
                }
            }
            Command::MoveItem {
                absolute_path,
                new_absolute_path,
            } => match fs::rename(absolute_path.as_ref(), new_absolute_path.as_ref()) {
                Ok(_) => CommandExecutionResult::Success,
                Err(e) => CommandExecutionResult::Error(e),
            },
            Command::CreateLink {
                absolute_path_dst,
                absolute_path_src,
                mode,
                kind,
            } => match mode {
                CreateLinkMode::Overwrite => {
                    // We remove: file, link, empty dir. Notably, non-empty dirs
                    // are left untouched
                    match fs::remove_dir(absolute_path_src.as_ref()) {
                        Ok(_) => (),
                        Err(e) => {
                            if e.kind() == io::ErrorKind::NotADirectory {
                                match fs::remove_file(absolute_path_src.as_ref()) {
                                    Ok(_) => (),
                                    Err(e) => return CommandExecutionResult::Error(e),
                                }
                            } else {
                                return CommandExecutionResult::Error(e);
                            }
                        }
                    }
                    Self::fs_link(kind, absolute_path_dst, absolute_path_src)
                }
                CreateLinkMode::CreateNew => {
                    if Path::new(absolute_path_src.as_ref()).exists() {
                        CommandExecutionResult::SuccessNoOp
                    } else {
                        Self::fs_link(kind, absolute_path_dst, absolute_path_src)
                    }
                }
                CreateLinkMode::RenameCreate => {
                    if Path::new(absolute_path_src.as_ref()).exists() {
                        let p = Self::find_new_name(&absolute_path_src);
                        Self::fs_link(kind, absolute_path_dst, p.into_boxed_str())
                    } else {
                        Self::fs_link(kind, absolute_path_dst, absolute_path_src)
                    }
                }
            },
            Command::Delete {
                absolute_path,
                mode,
            } => {
                // Try removing the path, if it exists
                let p = Path::new(absolute_path.as_ref());
                if p.exists() {
                    match mode {
                        DeleteMode::File => {
                            // Make sure this is not a link
                            if p.is_file() && !p.is_symlink() {
                                match fs::remove_file(p) {
                                    Ok(_) => CommandExecutionResult::Success,
                                    Err(e) => CommandExecutionResult::Error(e),
                                }
                            } else {
                                CommandExecutionResult::SuccessNoOp
                            }
                        }
                        DeleteMode::EmptyDir => {
                            if p.is_dir() && !p.is_symlink() {
                                match fs::remove_dir(p) {
                                    Ok(_) => CommandExecutionResult::Success,
                                    Err(e) => CommandExecutionResult::Error(e),
                                }
                            } else {
                                CommandExecutionResult::SuccessNoOp
                            }
                        }
                        DeleteMode::FileDir => {
                            if p.exists() && !p.is_symlink() {
                                if p.is_file() {
                                    match fs::remove_file(p) {
                                        Ok(_) => CommandExecutionResult::Success,
                                        Err(e) => CommandExecutionResult::Error(e),
                                    }
                                } else {
                                    match fs::remove_dir(p) {
                                        Ok(_) => CommandExecutionResult::Success,
                                        Err(e) => CommandExecutionResult::Error(e),
                                    }
                                }
                            } else {
                                CommandExecutionResult::SuccessNoOp
                            }
                        }
                        DeleteMode::Dir => {
                            if p.is_dir() && !p.is_symlink() {
                                match fs::remove_dir_all(p) {
                                    Ok(_) => CommandExecutionResult::Success,
                                    Err(e) => CommandExecutionResult::Error(e),
                                }
                            } else {
                                CommandExecutionResult::SuccessNoOp
                            }
                        }
                        DeleteMode::Symlink => {
                            if p.is_symlink() {
                                match fs::remove_file(p) {
                                    Ok(_) => CommandExecutionResult::Success,
                                    Err(e) => CommandExecutionResult::Error(e),
                                }
                            } else {
                                CommandExecutionResult::SuccessNoOp
                            }
                        }
                        DeleteMode::Any => {
                            // File or link
                            match fs::remove_file(p) {
                                Ok(_) => CommandExecutionResult::Success,
                                Err(e) => match e.kind() {
                                    io::ErrorKind::IsADirectory => match fs::remove_dir(p) {
                                        Ok(_) => CommandExecutionResult::Success,
                                        Err(e) => CommandExecutionResult::Error(e),
                                    },
                                    io::ErrorKind::NotFound => CommandExecutionResult::SuccessNoOp,
                                    _ => CommandExecutionResult::Error(e),
                                },
                            }
                        }
                    }
                } else {
                    CommandExecutionResult::Success
                }
            }
        }
    }

    fn fs_link(
        kind: LinkKind,
        absolute_path_dst: Box<str>,
        absolute_path_src: Box<str>,
    ) -> CommandExecutionResult {
        if kind == LinkKind::H {
            match fs::hard_link(absolute_path_dst.as_ref(), absolute_path_src.as_ref()) {
                Ok(_) => CommandExecutionResult::SuccessPath(absolute_path_src),
                Err(e) => CommandExecutionResult::Error(e),
            }
        } else {
            #[cfg(unix)]
            match os::unix::fs::symlink(absolute_path_dst.as_ref(), absolute_path_src.as_ref()) {
                Ok(_) => CommandExecutionResult::SuccessPath(absolute_path_src),
                Err(e) => CommandExecutionResult::Error(e),
            }
            #[cfg(windows)]
            {
                // Windows has different functions for file and dir
                // symlinks. Just try both and see if any works
                match os::windows::fs::symlink_dir(
                    absolute_path_dst.as_ref(),
                    absolute_path_src.as_ref(),
                ) {
                    Ok(_) => CommandExecutionResult::SuccessPath(absolute_path_src),
                    Err(_) => {
                        match os::windows::fs::symlink_file(
                            absolute_path_dst.as_ref(),
                            absolute_path_src.as_ref(),
                        ) {
                            Ok(_) => CommandExecutionResult::SuccessPath(absolute_path_src),
                            Err(e) => CommandExecutionResult::Error(e),
                        }
                    }
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct UnlessSession {
    session_id: u64,
    wait_time_ms: u32,
}

impl UnlessSession {
    fn new_empty() -> Self {
        Self {
            session_id: 0,
            wait_time_ms: 0,
        }
    }

    fn remove(&mut self, session_id: u64) {
        if self.session_id == session_id {
            self.wait_time_ms = 0;
        }
    }

    fn fulfilled(&self, time_passed_ms: u32) -> bool {
        self.wait_time_ms <= time_passed_ms
    }

    fn remove_list(&mut self, session_ids: &[u64]) {
        if session_ids.contains(&self.session_id) {
            self.wait_time_ms = 0;
        }
    }
}

#[derive(Debug)]
struct AfterSessions {
    session_ids: Vec<u64>,
    wait_time_ms: u32,
}

impl AfterSessions {
    fn new_empty() -> Self {
        Self {
            session_ids: Vec::new(),
            wait_time_ms: 0,
        }
    }

    fn remove(&mut self, session_id: u64) {
        if let Some(index) = self.session_ids.iter().position(|x| *x == session_id) {
            self.session_ids.swap_remove(index);
            // Remove the timeout
            if self.session_ids.is_empty() {
                self.wait_time_ms = 0;
            }
        }
    }

    fn fulfilled(&self, time_passed_ms: u32) -> bool {
        // Wait time is set to 0 when the last session ID is removed,
        // so we don't need to check the list
        self.wait_time_ms <= time_passed_ms
    }

    fn remove_multiple(&mut self, session_ids: &[u64]) {
        self.session_ids.retain(|id| !session_ids.contains(id));
    }
}

#[derive(Debug)]
pub struct CommandExecutor {
    unless: UnlessSession,
    after: AfterSessions,
    command: Command,
    session_id: u64,
}

impl CommandExecutor {
    pub fn new(command_buf: &[u8], session_id: u64) -> Result<Self, DeserializationError> {
        // Length
        if command_buf.len() < 8 {
            return Err(DeserializationError::ValueExpected);
        }
        let total_len = u64_from_le_bytes(command_buf);
        let mut buf_used = 8;
        if total_len != (command_buf.len() - buf_used) as u64 {
            return Err(DeserializationError::LengthMismatch);
        }
        // Unless, after
        let flags = command_buf[buf_used];
        buf_used += 1;
        let unless = if (flags & 0b0000_0010) != 0 {
            let (used, wait_time_ms) =
                <u32 as TryBufDeserialize>::try_deserialize_from_buf(&command_buf[buf_used..])?;
            buf_used += used;
            if command_buf.len() < buf_used + 8 {
                return Err(DeserializationError::ValueExpected);
            }
            let session_id = u64_from_le_bytes(&command_buf[buf_used..]);
            buf_used += 8;
            UnlessSession {
                session_id,
                wait_time_ms,
            }
        } else {
            UnlessSession::new_empty()
        };
        let after = if (flags & 0b0000_0001) != 0 {
            let (used, wait_time_ms) =
                <u32 as TryBufDeserialize>::try_deserialize_from_buf(&command_buf[buf_used..])?;
            buf_used += used;
            let (used, count) =
                <u64 as TryBufDeserialize>::try_deserialize_from_buf(&command_buf[buf_used..])?;
            buf_used += used;
            let mut session_ids = Vec::with_capacity(count as usize);
            for _ in 0..count {
                if command_buf.len() < buf_used + 8 {
                    return Err(DeserializationError::ValueExpected);
                }
                let id = u64_from_le_bytes(&command_buf[buf_used..]);
                buf_used += 8;
                session_ids.push(id);
            }
            AfterSessions {
                session_ids,
                wait_time_ms,
            }
        } else {
            AfterSessions::new_empty()
        };
        // Command
        let (used, command) = Command::try_from_buf(&command_buf[buf_used..])?;
        if buf_used + used < command_buf.len() {
            warn!("ignoring extra data at the end of protocol message");
        }

        Ok(CommandExecutor {
            unless,
            after,
            command,
            session_id,
        })
    }

    /// Removes the `unless` dependency, if it exists and its id matches `session_id`
    pub fn remove_unless(&mut self, session_id: u64) {
        self.unless.remove(session_id);
    }

    /// Removes the `unless` dependency, if it exists and its id is in `session_ids`
    pub fn remove_unless_list(&mut self, session_ids: &[u64]) {
        self.unless.remove_list(session_ids);
    }

    pub fn remove_after(&mut self, session_id: u64) {
        self.after.remove(session_id);
    }

    pub fn remove_after_multiple(&mut self, session_ids: &[u64]) {
        self.after.remove_multiple(session_ids);
    }

    pub fn can_execute(&self, time_passed_ms: u32) -> bool {
        self.unless.fulfilled(time_passed_ms) && self.after.fulfilled(time_passed_ms)
    }

    /// Caller MUST first call self.can_execute() and only call this if it
    /// returns true
    pub fn execute_unchecked(
        self,
        executed_commands: &[CompactCommandSession],
    ) -> CommandExecutionResult {
        self.command.execute(executed_commands)
    }

    pub fn session_id(&self) -> u64 {
        self.session_id
    }
}

pub enum CommandExecutionResult {
    /// Child process that should be waited on. This varianr indicates success
    Process(process::Child),
    /// Command was successfully executed
    Success,
    /// Execution is considered successful, but nothing was done because some
    /// conditions were not met
    SuccessNoOp,
    /// Successful, the included path should be preserved for future references
    SuccessPath(Box<str>),
    /// Command was not successfully executed
    Error(io::Error),
    /// Referenced command was not found in executed command list
    /// This could be because:
    /// - the command was not sent/received
    /// - the command was of the wrong type (it did not create/append to a file)
    /// - the command failed
    SessionNotFound(u64),
}

// TODO(future): append \0 to command string when deserializing
fn c_system(command: &str) -> io::Result<()> {
    let s = CString::from_str(command)?;
    let ret = unsafe { libc::system(s.as_ptr()) };
    check_c_err(ret)
}

// Take from: https://stackoverflow.com/a/42773525
fn check_c_err<T: Ord + Default>(num: T) -> io::Result<()> {
    if num < T::default() {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Command representation that can be referenced by later commands. We make
/// use of the fact that commands can only reference these fields in previous
/// commands:
/// - ExecuteReceived: path of the file
/// - AppendToFileFromTransfer: path of the file
pub struct CompactCommandSession {
    session_id: u64,
    path: Box<str>,
}

impl CompactCommandSession {
    pub fn from_path(session_id: u64, path: Box<str>) -> Self {
        Self { session_id, path }
    }
}
