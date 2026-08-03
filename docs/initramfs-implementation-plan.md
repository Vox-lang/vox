# Initramfs Example Implementation Plan

> **Status:** Substantially realized — the plan's required syscalls ship. The
> compiler implements `mkdir`, `mount`/`unmount`, `mknod`, `symlink`,
> `pivot_root`, `execve`, `chdir`, `rmdir`, `is available` (access), and
> `Sleep for` (nanosleep), documented in LANGUAGE.md §Directories, Mounting,
> and Process Control; `examples/initramfs.vox` exists and the README pitches
> it as a working early-userspace init. (The example file's own "proposed"
> header comment is now stale.) Item-by-item completion of every phase below
> is not verified here. _(assessed 2026-08, vox v0.1.23)_

This document outlines what is needed to bring the initramfs example (`vox/examples/initramfs.vox`) from a syntax demonstration to a working Vox program.

---

## Overview

The initramfs example demonstrates early userspace initialization operations typically performed by initramfs/initrd scripts. To make this example functional, several new syscalls and language features need to be implemented in Vox.

---

## Required Syscalls

### Already Implemented
- `open` (2) - File opening
- `close` (3) - File closing
- `read` (0) - File reading
- `write` (1) - File writing
- `exit` (60) - Program termination

### New Syscalls Required

#### 1. mkdir (83) - Create Directory
**Current Syntax:**
```
Create a directory called "/proc".
```

**Implementation Requirements:**
- Parser: Recognize `Create a directory called '<path>'` pattern
- Codegen: Generate syscall 83 with path argument and mode 0755 (rwxr-xr-x)
- Error handling: Set error flag on failure

#### 2. mount (165) - Mount Filesystem
**Current Syntax:**
```
Mount "proc" at "/proc" with type "proc".
Mount "devpts" at "/dev/pts" with type devpts with options "gid=5,mode=620".
```

**Implementation Requirements:**
- Parser: Recognize `Mount "<source>" at '<target>' with type "<fstype>" [with options "<opts>"]`
- Codegen: Generate syscall 165 with:
  - source string (or NULL for "none" type)
  - target string
  - filesystem type string
  - mount flags (read-only, noexec, etc.)
  - options string (comma-separated key=value pairs)
- Error handling: Set error flag on failure

**Mount Flags to Support:**
- MS_MOVE (8192) - for moving mounts to new root
- MS_BIND (4096) - for bind mounts
- MS_RDONLY (1) - read-only
- MS_NOEXEC (8) - no execution
- MS_NOSUID (2) - no setuid

#### 3. mknod (133) - Create Device Node
**Current Syntax:**
```
Create a device node called "/dev/null" with type "c" major 1 minor 3.
```

**Implementation Requirements:**
- Parser: Recognize `Create a device node called '<path>' with type "<type>" major <maj> minor <min>`
  - Type can be "c" (character) or "b" (block)
- Codegen: Generate syscall 133 with:
  - path string
  - mode (S_IFCHR for character, S_IFBLK for block, plus permissions)
  - device number (major << 8 | minor)
- Error handling: Set error flag on failure

#### 4. symlink (88) - Create Symbolic Link
**Current Syntax:**
```
Create symbolic link from "/proc/self/fd" to "/dev/fd".
```

**Implementation Requirements:**
- Parser: Recognize `Create symbolic link from '<target>' to "<linkpath>"`
- Codegen: Generate syscall 88 with target and linkpath strings
- Error handling: Set error flag on failure

#### 5. access (21) - Check File Accessibility
**Current Syntax:**
```
While the root device is not available,
```

**Implementation Requirements:**
- Parser: Recognize `<path> is not available` or `<path> is available` patterns
- Codegen: Generate syscall 21 with F_OK flag (0) to check existence
- Error handling: Return false if syscall fails (file doesn't exist)

#### 6. nanosleep (35) - Sleep
**Current Syntax:**
```
Sleep for 100 milliseconds.
```

**Implementation Requirements:**
- Parser: Recognize `Sleep for <duration> milliseconds` (also support seconds)
- Codegen: Generate syscall 35 with timespec structure:
  - Convert milliseconds to seconds + nanoseconds
  - Fill timespec struct with tv_sec and tv_nsec
- Error handling: Set error flag on interruption

#### 7. pivot_root (155) - Switch Root Filesystem
**Current Syntax:**
```
Pivot root to "/newroot" with old root "/newroot/oldroot".
```

**Implementation Requirements:**
- Parser: Recognize `Pivot root to '<new_root>' with old root "<put_old>"`
- Codegen: Generate syscall 155 with new_root and put_old path strings
- Error handling: Set error flag on failure
- **Important**: Requires that put_old is under new_root

#### 8. chdir (80) - Change Directory
**Current Syntax:**
```
Change directory to "/".
```

**Implementation Requirements:**
- Parser: Recognize `Change directory to "<path>"`
- Codegen: Generate syscall 80 with path string
- Error handling: Set error flag on failure

#### 9. execve (59) - Execute Program
**Current Syntax:**
```
Execute "/sbin/init" with arguments [].
```

**Implementation Requirements:**
- Parser: Recognize `Execute '<path>' with arguments [<list>]`
- Codegen: Generate syscall 59 with:
  - path string
  - argv array (program name + arguments + NULL terminator)
  - envp array (environment variables, can be NULL to inherit)
- Error handling: Set error flag on failure (only returns on error)

---

## Parser Changes Required

### New Grammar Rules

#### Directory Creation
```
statement ::= "Create" "a" "directory" "called" STRING
```

#### Mount Operations
```
statement ::= "Mount" STRING "at" STRING "with" "type" STRING [ "with" "options" STRING ]
```

#### Device Node Creation
```
statement ::= "Create" "a" "device" "node" "called" STRING "with" "type" ("c" | "b") "major" NUMBER "minor" NUMBER
```

#### Symbolic Link Creation
```
statement ::= "Create" "symbolic" "link" "from" STRING "to" STRING
```

#### File Availability Check
```
expression ::= STRING "is" [ "not" ] "available"
```

#### Sleep
```
statement ::= "Sleep" "for" NUMBER ("milliseconds" | "seconds")
```

#### Pivot Root
```
statement ::= "Pivot" "root" "to" STRING "with" "old" "root" STRING
```

#### Change Directory
```
statement ::= "Change" "directory" "to" STRING
```

#### Execute
```
statement ::= "Execute" STRING "with" "arguments" list
```

### Expression Extensions

The file availability check needs to be integrated into the expression grammar for use in conditions:

```
condition ::= expression "is" [ "not" ] "available"
```

---

## Codegen Changes Required

### Assembly Routines

For each new syscall, an assembly routine needs to be added to the coreasm library:

#### mkdir
```asm
; mkdir(path, mode)
; rdi = path pointer
; rsi = mode (0755)
; rax = 83
```

#### mount
```asm
; mount(source, target, fstype, flags, options)
; rdi = source pointer (or NULL)
; rsi = target pointer
; rdx = fstype pointer
; rcx = flags
; r8 = options pointer
; rax = 165
```

#### mknod
```asm
; mknod(path, mode, dev)
; rdi = path pointer
; rsi = mode (S_IFCHR | 0666)
; rdx = device number (major << 8 | minor)
; rax = 133
```

#### symlink
```asm
; symlink(target, linkpath)
; rdi = target pointer
; rsi = linkpath pointer
; rax = 88
```

#### access
```asm
; access(path, mode)
; rdi = path pointer
; rsi = mode (F_OK = 0)
; rax = 21
```

#### nanosleep
```asm
; nanosleep(req, rem)
; rdi = req pointer (timespec struct)
; rsi = rem pointer (can be NULL)
; rax = 35
```

#### pivot_root
```asm
; pivot_root(new_root, put_old)
; rdi = new_root pointer
; rsi = put_old pointer
; rax = 155
```

#### chdir
```asm
; chdir(path)
; rdi = path pointer
; rax = 80
```

#### execve
```asm
; execve(path, argv, envp)
; rdi = path pointer
; rsi = argv pointer
; rdx = envp pointer (NULL to inherit)
; rax = 59
```

### Data Structure Handling

#### timespec for nanosleep
Need to construct timespec structure in memory:
```asm
timespec:
    .tv_sec  dq 0    ; seconds
    .tv_nsec dq 0    ; nanoseconds
```

#### argv array for execve
Need to construct NULL-terminated argument array:
```asm
argv:
    dq path_ptr      ; argv[0] = program name
    dq arg1_ptr      ; argv[1] = first argument
    dq arg2_ptr      ; argv[2] = second argument
    dq 0             ; NULL terminator
```

### String Constant Handling

Several syscalls require string constants that need to be:
1. Stored in the data section
2. Referenced by pointer at runtime
3. Properly null-terminated

Examples:
- Filesystem types: "proc", "sysfs", "devtmpfs", "devpts", "tmpfs", "ext4", "none"
- Mount options: "gid=5,mode=620"
- Device paths: "/proc", "/sys", "/dev", etc.

---

## Implementation Priority

### Phase 1: Basic Filesystem Operations (High Priority)
1. **mkdir** - Essential for creating directory structure
2. **chdir** - Needed for directory navigation
3. **access** - Required for checking file/device availability
4. **symlink** - Important for compatibility symlinks

### Phase 2: Mount Operations (High Priority)
1. **mount** - Core functionality for initramfs
2. **pivot_root** - Critical for root switching

### Phase 3: Device and Process Operations (Medium Priority)
1. **mknod** - Device node creation (may be optional with devtmpfs)
2. **nanosleep** - Polling/waiting functionality
3. **execve** - Process execution (already in brainstorm, needs implementation)

---

## Testing Strategy

### Unit Tests
For each syscall, create a minimal test:
```
mkdir_test.vox:
    Create a directory called "/tmp/test_vox_mkdir".
    On error print "mkdir failed", exit 1.
    Print "mkdir succeeded".
    Remove the directory "/tmp/test_vox_mkdir".
```

### Integration Tests
Test the initramfs example in a safe environment:
1. Use a chroot or container
2. Mount a test filesystem instead of real root
3. Verify each step succeeds
4. Check proper cleanup on error

### Error Handling Tests
Test error conditions:
- mkdir on existing directory
- mount with invalid filesystem type
- symlink with invalid target
- access on non-existent file
- pivot_root with invalid paths

---

## Constants and Flags

### File Permissions
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
0755 = rwxr-xr-x  (default directory)
0666 = rw-rw-rw-  (default file)
```

### Device Types
```
S_IFCHR = 020000  (character device)
S_IFBLK = 006000  (block device)
```

### Mount Flags
```
MS_RDONLY = 1
MS_NOSUID = 2
MS_NODEV = 4
MS_NOEXEC = 8
MS_SYNCHRONOUS = 16
MS_REMOUNT = 32
MS_BIND = 4096
MS_MOVE = 8192
```

### Access Modes
```
F_OK = 0   (existence)
R_OK = 4   (read)
W_OK = 2   (write)
X_OK = 1   (execute)
```

---

## Security Considerations

1. **Path Validation**: Ensure paths are properly null-terminated and within reasonable length
2. **Privilege Checks**: Many of these operations require root/CAP_SYS_ADMIN
3. **Race Conditions**: TOCTOU (time-of-check-time-of-use) vulnerabilities in access/check-then-use patterns
4. **Symbolic Link Attacks**: Symlinks can redirect operations to unintended locations
5. **Mount Namespace**: Consider using mount namespaces for isolation in advanced use cases

---

## Documentation Updates

### LANGUAGE.md
Add sections for:
- Directory operations (mkdir, rmdir, chdir, getcwd)
- Mount operations (mount, umount)
- Device operations (mknod)
- Symbolic links (symlink, readlink)
- File availability checks (access)
- Sleep operations (nanosleep)
- Root switching (pivot_root)
- Process execution (execve)

### SYSCALLS_BRAINSTORM.md
Update status from "proposed" to "implemented" as each syscall is completed.

### Examples
Add additional examples:
- Simple directory traversal
- Mount/unmount operations
- Device node creation
- Symbolic link management
- Process spawning with execve

---

## Dependencies

### External Dependencies
None required - all operations use direct Linux syscalls.

### Internal Dependencies
- Existing error handling infrastructure
- String constant handling in data section
- Buffer management for path strings
- Expression evaluation for conditions

---

## Success Criteria

The initramfs example is considered successfully implemented when:

1. All required syscalls are implemented and tested
2. The example compiles without errors
3. The example runs successfully in a test environment (chroot/container)
4. All error paths are tested and documented
5. Documentation is updated with new syntax and semantics
6. The example is added to the test suite

---

## Open Questions

1. **Mount Options Parsing**: How complex should mount option parsing be? Simple string pass-through or structured parsing?
2. **Device Node Creation**: Is mknod strictly necessary if devtmpfs is used? Many modern systems use devtmpfs which auto-creates devices.
3. **Environment Variables**: Should execve support custom environment variables, or just inherit parent's?
4. **Error Granularity**: How detailed should error reporting be? Generic "operation failed" or specific error codes?
5. **Namespace Support**: Should we support mount namespaces for advanced containerization use cases?

---

## References

- Linux syscalls: https://man7.org/linux/man-pages/man2/syscalls.2.html
- mount(2): https://man7.org/linux/man-pages/man2/mount.2.html
- pivot_root(2): https://man7.org/linux/man-pages/man2/pivot_root.2.html
- initramfs: https://www.kernel.org/doc/Documentation/filesystems/ramfs-rootfs-initramfs.txt
