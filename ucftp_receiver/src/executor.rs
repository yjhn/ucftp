//! Global command executor. Manages command dependencies and wait times

// TODO: maybe use a different thread/thread pool/tokio/smol
use log::{debug, error, info, trace, warn};

use std::{process, time::Instant};

use crate::message::{CommandExecutionResult, CommandExecutor, CompactCommandSession};

// Every time a command is executed, call its removal method on every other
// command and remove itself from `commands`
pub struct GlobalExecutor {
    pending_commands: Vec<CommandWithMetadata>,
    // Session IDs of previously executed commands
    // Needed to be able to check unless and after conditions
    // TODO: actually check those conditions when a new command arrives
    past_sessions: Vec<u64>,
    // Commands whose data (paths) can be referenced later
    past_commands_data: Vec<CompactCommandSession>,
    child_procs: Vec<process::Child>,
}

impl GlobalExecutor {
    pub fn new() -> Self {
        Self {
            pending_commands: Vec::new(),
            past_sessions: Vec::new(),
            past_commands_data: Vec::new(),
            child_procs: Vec::new(),
        }
    }

    pub fn add_pending(&mut self, mut command: CommandExecutor) {
        debug!("new command {} added to executor", command.session_id());
        // Check preconditions
        command.remove_unless_list(&self.past_sessions);
        command.remove_after_multiple(&self.past_sessions);

        // Try executing
        if command.can_execute(0) {
            info!("executing command from session {}", command.session_id());
            let session_id = command.session_id();
            self.process_result(
                command.execute_unchecked(&self.past_commands_data),
                session_id,
            );
        } else {
            let com_meta = CommandWithMetadata::new(command);
            self.pending_commands.push(com_meta);
        }
    }

    fn process_result(&mut self, c: CommandExecutionResult, session_id: u64) {
        match c {
            CommandExecutionResult::Process(child) => {
                info!("successfully executed session {}", session_id);
                self.child_procs.push(child);
            }
            CommandExecutionResult::Success => {
                info!("successfully executed session {}", session_id)
            }
            CommandExecutionResult::SuccessNoOp => {
                info!("successfully ignored session {}", session_id)
            }
            CommandExecutionResult::SuccessPath(p) => {
                info!(
                    "successfully executed session {}, storing path for later use",
                    session_id
                );
                let com = CompactCommandSession::from_path(session_id, p);
                self.past_commands_data.push(com);
            }
            CommandExecutionResult::Error(e) => {
                warn!("failed to execute session {}, error: {}", session_id, e)
            }
            CommandExecutionResult::SessionNotFound(s) => {
                warn!(
                    "session '{}' referenced by session {} not found",
                    s, session_id
                )
            }
        }
        // Remove session from conditions
        for c in self.pending_commands.iter_mut() {
            c.remove_unless(session_id);
            c.remove_after(session_id);
        }
        self.past_sessions.push(session_id);
    }

    /// Execute commands and perform related bookkeeping
    pub fn work(&mut self) {
        self.try_execute_commands();
        self.reap_children();
    }

    /// Try executing each command in the pending queue.
    fn try_execute_commands(&mut self) {
        // Vec::retain() does not work here
        if !self.pending_commands.is_empty() {
            let now = Instant::now();
            let mut i = 0;
            loop {
                let c = &self.pending_commands[i];
                if c.can_execute(now) {
                    let c = self.pending_commands.swap_remove(i);
                    let session = c.session_id();
                    self.process_result(c.execute_unchecked(&self.past_commands_data), session);
                } else {
                    i += 1;
                }
            }
        }
    }

    fn reap_children(&mut self) {
        self.child_procs.retain_mut(|p| match p.try_wait() {
            Ok(res) => res.is_none(),
            Err(e) => {
                debug!("error waiting for child process: {}", e);
                true
            }
        });
    }
}

struct CommandWithMetadata {
    // used for tracking whether the required timeouts of command sequencing
    // have elapsed
    init_time: Instant,
    command: CommandExecutor,
}

impl CommandWithMetadata {
    pub fn new(command: CommandExecutor) -> Self {
        Self {
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

    pub fn can_execute(&self, now: Instant) -> bool {
        self.command.can_execute(diff_ms(self.init_time, now))
    }

    #[must_use]
    pub fn execute_unchecked(
        self,
        executed_commands: &[CompactCommandSession],
    ) -> CommandExecutionResult {
        self.command.execute_unchecked(executed_commands)
    }

    fn session_id(&self) -> u64 {
        self.command.session_id()
    }
}

fn diff_ms(old: Instant, new: Instant) -> u32 {
    (new - old).as_millis() as u32
}

fn time_since(t: &Instant) -> u32 {
    let now = Instant::now();
    diff_ms(*t, now)
}
