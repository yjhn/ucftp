use ucftp_shared::{
    message::*,
    serialise::{BufDeserialize, DeserializationError, TryBufDeserialize, u64_from_le_bytes},
};

// TODO(future): make every string or byte array inside message point to places
// in buf using `ouroboros` or `yoke` crate
pub enum Command {
    ExecuteCommand {
        absolute_path: Box<str>,
        env_vars: Box<[(Box<str>, Box<str>)]>,
        program_args: Box<[Box<str>]>,
    },
    ExecuteCommandInShell {
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
        file_data: Box<[u8]>,
    },
    AppendToFile {
        absolute_path: Box<str>,
        mode: AppendMode,
        file_data: Box<[u8]>,
    },
    AppendToFileFromTransfer {
        transfer_session_id: u64,
        file_data: Box<[u8]>,
    },
    RenameItem {
        // TODO(thesis): no need to limit renaming/moving to fields and dirs. Links also work just fine
        absolute_path: Box<str>,
        // TODO(thesis): renaming should not differ from moving just by path
        // interpretation (relative vs absolute). Here new_name will be treated as
        // just a name, not a path
        new_name: Box<str>,
    },
    MoveItem {
        absolute_path: Box<str>,
        new_absolute_path: Box<str>,
    },
    CreateLink {
        // TODO(thesis): fix the wording to use absolute paths only
        absolute_path: Box<str>,
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
                    Command::ExecuteCommand {
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
                Ok((buf_used, Command::ExecuteCommandInShell { command }))
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
                Ok((
                    buf_used,
                    Command::CreateFile {
                        absolute_path,
                        mode,
                        file_data,
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
                        file_data,
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
                        file_data,
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
                let (used, absolute_path) = Box::try_deserialize_from_buf(&buf[buf_used..])?;
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
                        absolute_path,
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
}

#[derive(Clone, Copy)]
struct UnlessSession {
    session_id: u64,
    wait_time_ms: u32,
}

struct AfterSessions {
    session_ids: Vec<u64>,
    wait_time_ms: u32,
}

pub struct CommandExecutor {
    unless: Option<UnlessSession>,
    after: Option<AfterSessions>,
    command: Command,
}

impl CommandExecutor {
    pub fn new(command_buf: &[u8]) -> Result<Self, DeserializationError> {
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
        let mut unless = None;
        if (flags & 0b0000_0010) != 0 {
            let (used, wait_time_ms) =
                <u32 as TryBufDeserialize>::try_deserialize_from_buf(&command_buf[buf_used..])?;
            buf_used += used;
            if command_buf.len() < buf_used + 8 {
                return Err(DeserializationError::ValueExpected);
            }
            let session_id = u64_from_le_bytes(&command_buf[buf_used..]);
            buf_used += 8;
            unless = Some(UnlessSession {
                session_id,
                wait_time_ms,
            })
        }
        let mut after = None;
        if (flags & 0b0000_0001) != 0 {
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
            after = Some(AfterSessions {
                session_ids,
                wait_time_ms,
            });
        }
        // Command
        let (used, command) = Command::try_from_buf(&command_buf[buf_used..])?;
        if buf_used + used < command_buf.len() {
            // TODO: use proper logging with levels, e.g. log crate
            eprintln!("ignoring extra data at the end of protocol message");
        }

        Ok(CommandExecutor {
            unless,
            after,
            command,
        })
    }
}
