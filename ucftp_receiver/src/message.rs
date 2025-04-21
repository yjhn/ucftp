use ucftp_shared::{
    message::*,
    serialise::{BufDeserialise, u64_from_le_bytes},
};

/// Protocol message deserialization and execution
// Flow:
// 1. init packet is supplied
// 2. decide which type of command it is
// 3. start decoding its arguments
// 4. deserialise in full fields only:
//    - all fields are Option<T>
//    - each of them is either fully populated or empty
//    - we also hold a buffer of remaining data
//    - each time that buffer is appended to, we try decoding more fields
//      This has the potential to waste substantial amount of computation
//      if the command has many string arguments
//      Maybe each command could hold an enum that holds info of what remains
//      to be read?
// use std::num::{NonZeroU32, NonZeroUsize};

// Values are cascading: when first value is done, we go to second
// enum ExecCoRemDec {
//     AbsolutePath(NonZeroUsize),
//     EnvVars {
//         number: NonZeroU32,
//         length_remaining: usize,
//     },
//     ProgramArgs {
//         number: NonZeroU32,
//         length_remaining: usize,
//     },
//     None,
// }

// enum ExecCoInShellRemDec {
//     Command(NonZeroUsize),
//     None,
// }

// enum SetEnvVarsRemDec {

//     None
// }

// pub enum MessageStreamingDeserialiser {
//     ExecuteCommand { remaining: ExecCoRemDec },
//     ExecuteCommandInShell { remaining: ExecCoInShellRemDec },
//     SetEnvVars,
// }

// TODO(future): streaming deserialisation to avoid keeping all the state around
// aead crate used by hpke does not have traits for decrypting into a provided buffer.
// The only options are:
// - in place - hpke does this
// - create vec with contents as a result

// TODO(future): make every string or byte array inside message point to places
// in buf using `ouroboros` crate
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
    fn try_from_buf(buf: &[u8]) -> Result<(usize, Command), CommandError> {
        let mut buf_used = 0;
        match buf[0] {
            0 => todo!(),
            _ => Err(CommandError::UnknownType),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CommandError {
    /// Command length does not match the one indicated in packet
    LengthMismatch,
    /// Unknown command type
    UnknownType,
    /// Some string in command is not proper UTF-8
    StringEncoding,
    /// Some field has an unexpected value, e.g. a u32 field has value > u32::MAX
    BadFieldValue,
}

struct UnlessSession {
    session_id: u64,
    wait_time: u32,
}

struct AfterSessions {
    session_ids: Vec<u64>,
}

pub struct CommandExecutor {
    unless: Option<UnlessSession>,
    after: Option<AfterSessions>,
    command: Command,
}

impl CommandExecutor {
    pub fn new(command_buf: &[u8]) -> Result<Self, CommandError> {
        // Length
        let total_len = u64_from_le_bytes(command_buf);
        let mut buf_used = 8;
        if total_len != (command_buf.len() - buf_used) as u64 {
            return Err(CommandError::LengthMismatch);
        }
        // Unless, after
        let flags = command_buf[buf_used];
        buf_used += 1;
        let mut unless = None;
        if (flags & 0b0000_0010) != 0 {
            // TODO(impl): use actual compressed u32, not compressed u64. That way
            // wrong values are unrepresentable
            let (used, wait_time) =
                <u32 as BufDeserialise>::deserialise_from_buf(&command_buf[buf_used..]);
            buf_used += used;
            let session_id = u64_from_le_bytes(&command_buf[buf_used..]);
            buf_used += 8;
            unless = Some(UnlessSession {
                session_id,
                wait_time,
            })
        }
        let mut after = None;
        if (flags & 0b0000_0001) != 0 {
            let (used, wait_time) =
                <u32 as BufDeserialise>::deserialise_from_buf(&command_buf[buf_used..]);
            buf_used += used;
            let (used, count) =
                <u64 as BufDeserialise>::deserialise_from_buf(&command_buf[buf_used..]);
            let mut session_ids = Vec::with_capacity(count as usize);
            for _ in 0..count {
                let id = u64_from_le_bytes(&command_buf[buf_used..]);
                buf_used += 8;
                session_ids.push(id);
            }
            after = Some(AfterSessions { session_ids });
        }
        // Type
        let command = match Command::try_from_buf(&command_buf[buf_used..]) {
            Ok((used, c)) => {
                buf_used += used;
                if buf_used < command_buf.len() {
                    eprintln!("ignoring extra data at the end of protocol message");
                }
                c
            }
            Err(e) => return Err(e),
        };

        Ok(CommandExecutor {
            unless,
            after,
            command: todo!(),
        })
    }
}
