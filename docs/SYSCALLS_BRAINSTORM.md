# Linux Syscalls Brainstorm for English Compiler

This document explores Linux syscalls that could be leveraged to add powerful features to the English programming language.

## Currently Implemented

| Syscall | Number | Current Usage |
|---------|--------|---------------|
| `read` | 0 | File/stdin reading |
| `write` | 1 | File/stdout writing |
| `open` | 2 | File opening |
| `close` | 3 | File closing |
| `exit` | 60 | Program termination |
| `mmap` | 9 | Memory allocation (buffers) |
| `munmap` | 11 | Memory deallocation (buffers) |

---

## File System Operations

### Directory Operations

| Syscall | Number | Description | Proposed Syntax |
|---------|--------|-------------|-----------------|
| `mkdir` | 83 | Create directory | `Create a directory called "logs".` |
| `rmdir` | 84 | Remove empty directory | `Remove the directory "temp".` |
| `chdir` | 80 | Change working directory | `Change directory to "/home/user".` |
| `getcwd` | 79 | Get current directory | `Get current directory into path.` |
| `getdents64` | 217 | List directory contents | `List files in "." into filelist.` |

**Example:**
```english
Create a directory called "output".
Change directory to "output".
Get current directory into cwd.
Print cwd.
```

### File Metadata

| Syscall | Number | Description | Proposed Syntax |
|---------|--------|-------------|-----------------|
| `stat` | 4 | Get file info | `Get info about "file.txt" into fileinfo.` |
| `fstat` | 5 | Get file info by fd | `Get info about myfile into fileinfo.` |
| `lstat` | 6 | Get symlink info | `Get link info about "link" into linkinfo.` |
| `access` | 21 | Check file permissions | `If "file.txt" is readable then...` |
| `chmod` | 90 | Change permissions | `Set permissions of "script.sh" to executable.` |
| `chown` | 92 | Change ownership | `Set owner of "file.txt" to "user".` |
| `rename` | 82 | Rename/move file | `Rename "old.txt" to "new.txt".` |
| `unlink` | 87 | Delete file | `Delete "temp.txt".` |
| `link` | 86 | Create hard link | `Link "original" to "hardlink".` |
| `symlink` | 88 | Create symbolic link | `Create symbolic link from "target" to "link".` |
| `readlink` | 89 | Read symlink target | `Read link "symlink" into target.` |
| `truncate` | 76 | Resize file | `Truncate "file.txt" to 0 bytes.` |

**Example:**
```english
If "config.txt" exists then,
    get info about "config.txt" into info,
    print info's size.

If "output.log" is writable then,
    delete "output.log".
```

### Advanced File Operations

| Syscall | Number | Description | Proposed Syntax |
|---------|--------|-------------|-----------------|
| `lseek` | 8 | Seek in file | `Seek to position 100 in myfile.` |
| `pread64` | 17 | Read at offset | `Read 50 bytes at position 100 from myfile into buffer.` |
| `pwrite64` | 18 | Write at offset | `Write buffer at position 100 to myfile.` |
| `sendfile` | 40 | Copy between fds | `Copy from source to dest.` |
| `splice` | 275 | Move data between fds | `Splice from pipe to file.` |
| `fallocate` | 285 | Allocate file space | `Allocate 1024 bytes for myfile.` |

---

## Process Management

### Process Creation & Control

| Syscall | Number | Description | Proposed Syntax |
|---------|--------|-------------|-----------------|
| `fork` | 57 | Create child process | `Fork into child.` |
| `vfork` | 58 | Create child (shared mem) | `Fork quickly into child.` |
| `execve` | 59 | Execute program | `Execute "/bin/ls" with arguments args.` |
| `wait4` | 61 | Wait for child | `Wait for child into status.` |
| `kill` | 62 | Send signal | `Send signal TERM to process pid.` |
| `getpid` | 39 | Get process ID | `Get process id into pid.` |
| `getppid` | 110 | Get parent PID | `Get parent process id into ppid.` |

**Example:**
```english
Fork into child.
If child is 0 then,
    execute "/bin/echo" with arguments ["hello"],
    exit 0.
Wait for child into status.
Print "Child exited with " then status.
```

### Process Information

| Syscall | Number | Description | Proposed Syntax |
|---------|--------|-------------|-----------------|
| `getuid` | 102 | Get user ID | `Get user id into uid.` |
| `getgid` | 104 | Get group ID | `Get group id into gid.` |
| `geteuid` | 107 | Get effective UID | `Get effective user id into euid.` |
| `getegid` | 108 | Get effective GID | `Get effective group id into egid.` |
| `setuid` | 105 | Set user ID | `Set user id to 1000.` |
| `setgid` | 106 | Set group ID | `Set group id to 1000.` |

---

## Networking

### Socket Operations

| Syscall | Number | Description | Proposed Syntax |
|---------|--------|-------------|-----------------|
| `socket` | 41 | Create socket | `Create a TCP socket called "server".` |
| `bind` | 49 | Bind to address | `Bind server to port 8080.` |
| `listen` | 50 | Listen for connections | `Listen on server with backlog 10.` |
| `accept` | 43 | Accept connection | `Accept connection on server into client.` |
| `connect` | 42 | Connect to server | `Connect client to "localhost" port 80.` |
| `send` | 44 | Send data | `Send message to client.` |
| `recv` | 45 | Receive data | `Receive from client into buffer.` |
| `sendto` | 44 | Send to address (UDP) | `Send message to address.` |
| `recvfrom` | 45 | Receive with address | `Receive from socket into buffer and address.` |
| `shutdown` | 48 | Shutdown socket | `Shutdown client for writing.` |
| `getsockname` | 51 | Get local address | `Get address of server into addr.` |
| `getpeername` | 52 | Get remote address | `Get peer address of client into addr.` |
| `setsockopt` | 54 | Set socket option | `Set option REUSEADDR on server.` |
| `getsockopt` | 55 | Get socket option | `Get option REUSEADDR from server into value.` |

**Example:**
```english
Create a TCP socket called "server".
Bind server to port 8080.
Listen on server with backlog 10.
Print "Listening on port 8080...".

Loop forever,
    accept connection on server into client,
    receive from client into request,
    send "HTTP/1.1 200 OK\r\n\r\nHello!" to client,
    close client.
```

### DNS & Address Resolution (via helper functions)

```english
Resolve "example.com" into address.
Connect client to address port 443.
```

---

## Memory Management

| Syscall | Number | Description | Proposed Syntax |
|---------|--------|-------------|-----------------|
| `mmap` | 9 | Map memory/files | `Map "largefile.dat" into memory as region.` |
| `munmap` | 11 | Unmap memory | `Unmap region.` |
| `mprotect` | 10 | Set memory protection | `Protect region as readonly.` |
| `mremap` | 25 | Remap memory | `Resize region to 4096 bytes.` |
| `madvise` | 28 | Memory advice | `Advise region as sequential.` |
| `mlock` | 149 | Lock memory | `Lock region in memory.` |
| `munlock` | 150 | Unlock memory | `Unlock region.` |

**Example:**
```english
Map "database.db" into memory as db.
(Access db like a buffer)
Read 100 bytes from db at offset 0 into header.
Unmap db.
```

---

## Time & Timers

| Syscall | Number | Description | Proposed Syntax |
|---------|--------|-------------|-----------------|
| `time` | 201 | Get time in seconds | `Get time into timestamp.` |
| `gettimeofday` | 96 | Get time with microseconds | `Get precise time into now.` |
| `clock_gettime` | 228 | High-res time | `Get monotonic time into elapsed.` |
| `nanosleep` | 35 | Sleep | `Sleep for 1 second.` / `Wait 500 milliseconds.` |
| `alarm` | 37 | Set alarm | `Set alarm for 30 seconds.` |
| `timer_create` | 222 | Create timer | `Create timer called "heartbeat".` |
| `timer_settime` | 223 | Set timer | `Set heartbeat to fire every 1 second.` |

**Example:**
```english
Get time into start.
(... do work ...)
Get time into end.
Set elapsed to end minus start.
Print "Elapsed: " then elapsed then " seconds".

Sleep for 2 seconds.
Print "Done waiting!".
```

---

## Signals

| Syscall | Number | Description | Proposed Syntax |
|---------|--------|-------------|-----------------|
| `rt_sigaction` | 13 | Set signal handler | `On signal INTERRUPT, call cleanup.` |
| `rt_sigprocmask` | 14 | Block/unblock signals | `Block signal INTERRUPT.` |
| `rt_sigpending` | 127 | Check pending signals | `Get pending signals into pending.` |
| `rt_sigsuspend` | 130 | Wait for signal | `Wait for any signal.` |
| `sigaltstack` | 131 | Set alt signal stack | `Set signal stack to altstack.` |

**Example:**
```english
Define cleanup as:
    print "Caught interrupt, cleaning up...",
    close all files,
    exit 0.

On signal INTERRUPT, call cleanup.
On signal TERMINATE, call cleanup.

(Main program)
Loop forever,
    read from stdin into line,
    print line.
```

---

## Pipes & IPC

### Pipes

| Syscall | Number | Description | Proposed Syntax |
|---------|--------|-------------|-----------------|
| `pipe` | 22 | Create pipe | `Create a pipe called "channel".` |
| `pipe2` | 293 | Create pipe with flags | `Create a non-blocking pipe called "channel".` |
| `dup` | 32 | Duplicate fd | `Duplicate stdin into saved_stdin.` |
| `dup2` | 33 | Duplicate to specific fd | `Redirect stdout to logfile.` |

**Example:**
```english
Create a pipe called "channel".
Fork into child.

If child is 0 then,
    close channel's read end,
    write "Hello from child!" to channel,
    close channel's write end,
    exit 0.

Close channel's write end.
Read from channel into message.
Print "Parent received: " then message.
Close channel's read end.
Wait for child.
```

### System V IPC

| Syscall | Number | Description | Proposed Syntax |
|---------|--------|-------------|-----------------|
| `shmget` | 29 | Get shared memory | `Create shared memory "shm" of size 4096.` |
| `shmat` | 30 | Attach shared memory | `Attach shared memory "shm" into region.` |
| `shmdt` | 67 | Detach shared memory | `Detach region.` |
| `shmctl` | 31 | Control shared memory | `Remove shared memory "shm".` |
| `semget` | 64 | Get semaphore | `Create semaphore "lock".` |
| `semop` | 65 | Semaphore operation | `Acquire lock.` / `Release lock.` |
| `msgget` | 68 | Get message queue | `Create message queue "mailbox".` |
| `msgsnd` | 69 | Send message | `Send message to mailbox.` |
| `msgrcv` | 70 | Receive message | `Receive from mailbox into message.` |

---

## Polling & Event Handling

| Syscall | Number | Description | Proposed Syntax |
|---------|--------|-------------|-----------------|
| `poll` | 7 | Wait for events | `Wait for input on [stdin, socket] into ready.` |
| `select` | 23 | Wait for multiple fds | `Select readable from [fd1, fd2] into ready.` |
| `epoll_create` | 213 | Create epoll instance | `Create event monitor called "events".` |
| `epoll_ctl` | 233 | Control epoll | `Watch socket for input in events.` |
| `epoll_wait` | 232 | Wait for events | `Wait for events into triggered.` |
| `eventfd` | 284 | Create event fd | `Create event counter called "signal".` |
| `timerfd_create` | 283 | Create timer fd | `Create timer fd called "tick".` |
| `signalfd` | 282 | Create signal fd | `Create signal fd for INTERRUPT called "sigfd".` |

**Example:**
```english
Create event monitor called "events".
Watch server for connections in events.
Watch stdin for input in events.

Loop forever,
    wait for events into triggered with timeout 1000,
    for each event in triggered,
        if event is server then,
            accept connection on server into client,
            watch client for input in events.
        if event is stdin then,
            read from stdin into command,
            if command is "quit" then exit 0.
        if event is client then,
            receive from client into data,
            process data.
```

---

## System Information

| Syscall | Number | Description | Proposed Syntax |
|---------|--------|-------------|-----------------|
| `uname` | 63 | Get system info | `Get system info into sysinfo.` |
| `sysinfo` | 99 | Get system stats | `Get system stats into stats.` |
| `getrusage` | 98 | Get resource usage | `Get resource usage into usage.` |
| `times` | 100 | Get process times | `Get process times into times.` |
| `getrlimit` | 97 | Get resource limits | `Get file limit into maxfiles.` |
| `setrlimit` | 160 | Set resource limits | `Set file limit to 1024.` |
| `prctl` | 157 | Process control | `Set process name to "worker".` |

**Example:**
```english
Get system info into sysinfo.
Print "Running on " then sysinfo's nodename.
Print "Kernel: " then sysinfo's release.

Get system stats into stats.
Print "Uptime: " then stats's uptime then " seconds".
Print "Free RAM: " then stats's freeram then " bytes".
```

---

## Miscellaneous

| Syscall | Number | Description | Proposed Syntax |
|---------|--------|-------------|-----------------|
| `getrandom` | 318 | Get random bytes | `Get 16 random bytes into key.` |
| `ioctl` | 16 | Device control | `Control terminal for size into dimensions.` |
| `fcntl` | 72 | File control | `Set myfile to non-blocking.` |
| `flock` | 73 | File locking | `Lock myfile exclusively.` / `Unlock myfile.` |
| `sync` | 162 | Sync filesystems | `Sync all files.` |
| `fsync` | 74 | Sync file | `Sync myfile.` |
| `fdatasync` | 75 | Sync file data | `Sync data of myfile.` |

---

## Priority Implementation Suggestions

### High Priority (Most Useful)
1. **Networking** - `socket`, `bind`, `listen`, `accept`, `connect`, `send`, `recv`
2. **Directory ops** - `mkdir`, `rmdir`, `chdir`, `getcwd`, `getdents64`
3. **File metadata** - `stat`, `rename`, `unlink`, `chmod`
4. **Time** - `time`, `nanosleep`
5. **Random** - `getrandom`

### Medium Priority
1. **Pipes** - `pipe`, `dup2`
2. **Process** - `fork`, `execve`, `wait4`
3. **Signals** - `rt_sigaction`
4. **Polling** - `poll`, `epoll_*`
5. **File ops** - `lseek`, `truncate`

### Lower Priority (Advanced)
1. **Memory mapping** - `mmap`, `munmap`
2. **IPC** - `shmget`, `semget`, `msgget`
3. **Timers** - `timer_create`, `timerfd_create`
4. **System info** - `uname`, `sysinfo`

---

## Implementation Notes

### Socket Type Constants
```
AF_INET = 2       (IPv4)
AF_INET6 = 10     (IPv6)
AF_UNIX = 1       (Unix domain)
SOCK_STREAM = 1   (TCP)
SOCK_DGRAM = 2    (UDP)
```

### Signal Constants
```
SIGHUP = 1
SIGINT = 2
SIGQUIT = 3
SIGKILL = 9
SIGTERM = 15
SIGCHLD = 17
SIGCONT = 18
SIGSTOP = 19
```

### File Permission Constants
```
S_IRUSR = 0400   (owner read)
S_IWUSR = 0200   (owner write)
S_IXUSR = 0100   (owner execute)
S_IRGRP = 0040   (group read)
S_IWGRP = 0020   (group write)
S_IXGRP = 0010   (group execute)
S_IROTH = 0004   (other read)
S_IWOTH = 0002   (other write)
S_IXOTH = 0001   (other execute)
```

---

## Example: Complete HTTP Server

```english
(Simple HTTP server in English)

Enable error catching.
Create a TCP socket called "server".
Set option REUSEADDR on server.
Bind server to port 8080.
Listen on server with backlog 10.
Print "Server listening on port 8080...".

Create a buffer called "request".
Create a buffer called "response".

Loop forever,
    accept connection on server into client,
    receive from client into request,
    
    (Build response)
    set response to "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<h1>Hello from English!</h1>",
    
    send response to client,
    close client.
```

---

## Example: File Watcher

```english
(Watch a directory for changes)

Create event monitor called "watcher".
Watch directory "/var/log" for changes in watcher.

Loop forever,
    wait for events into changes,
    for each change in changes,
        print "File changed: " then change's filename.
```

---

## Next Steps

1. Prioritize which syscalls to implement first based on user needs
2. Design consistent English syntax for each category
3. Implement stdlib assembly routines for each syscall
4. Add parser support for new constructs
5. Add codegen support
6. Write tests and examples
7. Document in LANGUAGE.md
