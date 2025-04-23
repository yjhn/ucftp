//! Global command executor. Manages command dependencies and wait times

// TODO: maybe use a different thread/thread pool/tokio/smol

use std::time::Instant;

use crate::message::CommandExecutor;

// Every time a command is executed, call its removal method on every other
// command and remove itself from `commands`
pub struct GlobalExecutor {
    commands: Vec<CommandWithMetadata>,
    // Session IDs of previously executed commands
    past_commands: Vec<u64>,
}

struct CommandWithMetadata {
    session_id: u64,
    // used for tracking whether the required timeouts of command sequencing
    // have elapsed
    init_time: Instant,
    command: CommandExecutor,
}

impl CommandWithMetadata {
    pub fn new(session_id: u64, command: CommandExecutor) -> Self {
        Self {
            session_id,
            init_time: Instant::now(),
            command,
        }
    }

    pub fn remove_unless(&mut self, session_id: u64) {
        self.command.remove_unless(session_id);
    }

    pub fn remove_after(&mut self, session_id: u64) {
        self.command.remove_after(session_id);
    }

    /// Try to execute the command. Command is executed if unless and after
    /// conditions are met or empty. If command is executed, Some(success) is
    /// returned, where `success` indicates if command execution was susccessful,
    /// e.g. whether file execution succeeded.
    pub fn try_execute(&self, now: Instant) -> Option<bool> {
        self.command
            .execute_if_allowed(diff_ms(self.init_time, now))
    }
}

fn diff_ms(old: Instant, new: Instant) -> u32 {
    (new - old).as_millis() as u32
}

fn time_since(t: &Instant) -> u32 {
    let now = Instant::now();
    (now - *t).as_millis() as u32
}
