// xev backend selector — forces epoll on Linux instead of default io_uring.
// On Windows (IOCP) and other platforms, uses the default backend.
const raw = @import("xev_raw");
const builtin = @import("builtin");

const is_linux = builtin.os.tag == .linux;
const Epoll = if (is_linux) raw.Epoll else void;

// Core types
pub const Loop = if (is_linux) Epoll.Loop else raw.Loop;
pub const Completion = if (is_linux) Epoll.Completion else raw.Completion;
pub const Result = if (is_linux) Epoll.Result else raw.Result;
pub const ReadBuffer = if (is_linux) Epoll.ReadBuffer else raw.ReadBuffer;
pub const WriteBuffer = if (is_linux) Epoll.WriteBuffer else raw.WriteBuffer;
pub const Options = if (is_linux) Epoll.Options else raw.Options;
pub const RunMode = if (is_linux) Epoll.RunMode else raw.RunMode;
pub const Callback = if (is_linux) Epoll.Callback else raw.Callback;
pub const CallbackAction = if (is_linux) Epoll.CallbackAction else raw.CallbackAction;
pub const CompletionState = if (is_linux) Epoll.CompletionState else raw.CompletionState;
pub const Sys = if (is_linux) Epoll.Sys else raw.Sys;

// Error types
pub const AcceptError = if (is_linux) Epoll.AcceptError else raw.AcceptError;
pub const CancelError = if (is_linux) Epoll.CancelError else raw.CancelError;
pub const CloseError = if (is_linux) Epoll.CloseError else raw.CloseError;
pub const ConnectError = if (is_linux) Epoll.ConnectError else raw.ConnectError;
pub const ShutdownError = if (is_linux) Epoll.ShutdownError else raw.ShutdownError;
pub const WriteError = if (is_linux) Epoll.WriteError else raw.WriteError;
pub const ReadError = if (is_linux) Epoll.ReadError else raw.ReadError;
pub const PollError = if (is_linux) Epoll.PollError else raw.PollError;
pub const PollEvent = if (is_linux) Epoll.PollEvent else raw.PollEvent;

// Watcher types
pub const Async = if (is_linux) Epoll.Async else raw.Async;
pub const File = if (is_linux) Epoll.File else raw.File;
pub const Process = if (is_linux) Epoll.Process else raw.Process;
pub const Stream = if (is_linux) Epoll.Stream else raw.Stream;
pub const Timer = if (is_linux) Epoll.Timer else raw.Timer;
pub const TCP = if (is_linux) Epoll.TCP else raw.TCP;
pub const UDP = if (is_linux) Epoll.UDP else raw.UDP;

// Queue types
pub const WriteQueue = if (is_linux) Epoll.WriteQueue else raw.WriteQueue;
pub const WriteRequest = if (is_linux) Epoll.WriteRequest else raw.WriteRequest;

// Metadata
pub const dynamic = if (is_linux) Epoll.dynamic else raw.dynamic;
pub const backend = if (is_linux) Epoll.backend else raw.backend;
pub const available = if (is_linux) Epoll.available else raw.available;
pub const noopCallback = if (is_linux) Epoll.noopCallback else raw.noopCallback;

// Non-backend-specific types (always from raw xev)
pub const Backend = raw.Backend;
pub const ThreadPool = raw.ThreadPool;
