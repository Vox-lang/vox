; time.asm - Time and sleep macros for English Compiler
; Provides time operations: get time, sleep, precise timing, timers, date components

; Linux x86_64 syscall numbers
%define SYS_NANOSLEEP       35
%define SYS_GETTIMEOFDAY    96
%define SYS_TIME            201
%define SYS_CLOCK_GETTIME   228

; Clock IDs for clock_gettime
%define CLOCK_REALTIME      0
%define CLOCK_MONOTONIC     1

; Timespec structure offsets
; struct timespec { time_t tv_sec; long tv_nsec; }
%define TIMESPEC_SEC        0
%define TIMESPEC_NSEC       8
%define TIMESPEC_SIZE       16

; Timeval structure offsets (for gettimeofday)
; struct timeval { time_t tv_sec; suseconds_t tv_usec; }
%define TIMEVAL_SEC         0
%define TIMEVAL_USEC        8
%define TIMEVAL_SIZE        16

; Timer structure offsets
; struct timer { start_real:8, start_mono_sec:8, start_mono_nsec:8, 
;                end_real:8, end_mono_sec:8, end_mono_nsec:8, running:8 }
%define TIMER_START_REAL        0
%define TIMER_START_MONO_SEC    8
%define TIMER_START_MONO_NSEC   16
%define TIMER_END_REAL          24
%define TIMER_END_MONO_SEC      32
%define TIMER_END_MONO_NSEC     40
%define TIMER_RUNNING           48
%define TIMER_SIZE              56

; DateTime structure offsets (broken-down time)
; struct datetime { unix:8, year:8, month:8, day:8, hour:8, minute:8, second:8 }
%define DATETIME_UNIX       0
%define DATETIME_YEAR       8
%define DATETIME_MONTH      16
%define DATETIME_DAY        24
%define DATETIME_HOUR       32
%define DATETIME_MINUTE     40
%define DATETIME_SECOND     48
%define DATETIME_SIZE       56

; Conversion constants
%define NANOSECONDS_PER_SECOND      1000000000
%define NANOSECONDS_PER_MILLISECOND 1000000
%define MICROSECONDS_PER_SECOND     1000000
%define MILLISECONDS_PER_SECOND     1000

; Time constants
%define SECONDS_PER_MINUTE  60
%define SECONDS_PER_HOUR    3600
%define SECONDS_PER_DAY     86400
%define DAYS_PER_YEAR       365
%define DAYS_PER_LEAP_YEAR  366
%define EPOCH_YEAR          1970

section .data
    ; Days in each month (non-leap year)
    _days_in_month: db 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31

section .text

; ============================================================================
; GET TIME - Returns seconds since Unix epoch
; ============================================================================

; Get current time in seconds
; Returns: time in rax (seconds since epoch)
%macro TIME_GET 0
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    
    mov rax, SYS_TIME
    xor rdi, rdi                    ; NULL - return time in rax
    syscall
    
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
%endmacro

; Get current time into a variable (memory location)
; Args: destination memory address
%macro TIME_GET_INTO 1
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    
    mov rax, SYS_TIME
    xor rdi, rdi
    syscall
    
    mov [%1], rax
    
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
%endmacro

; ============================================================================
; PRECISE TIME - High resolution timing
; ============================================================================

; Get monotonic time (for measuring durations, not affected by clock changes)
; Args: pointer to timespec struct (16 bytes: sec + nsec)
; Returns: 0 on success in rax
%macro TIME_MONOTONIC 1
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    
    mov rax, SYS_CLOCK_GETTIME
    mov rdi, CLOCK_MONOTONIC
    mov rsi, %1                     ; pointer to timespec
    syscall
    
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
%endmacro

; Get realtime (wall clock) with nanosecond precision
; Args: pointer to timespec struct (16 bytes: sec + nsec)
; Returns: 0 on success in rax
%macro TIME_REALTIME 1
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    
    mov rax, SYS_CLOCK_GETTIME
    mov rdi, CLOCK_REALTIME
    mov rsi, %1                     ; pointer to timespec
    syscall
    
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
%endmacro

; Get time with microsecond precision (gettimeofday)
; Args: pointer to timeval struct (16 bytes: sec + usec)
; Returns: 0 on success in rax
%macro TIME_PRECISE 1
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    
    mov rax, SYS_GETTIMEOFDAY
    mov rdi, %1                     ; pointer to timeval
    xor rsi, rsi                    ; timezone = NULL
    syscall
    
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
%endmacro

; ============================================================================
; SLEEP - Pause execution
; ============================================================================

; Sleep for specified number of seconds
; Args: seconds (immediate or register)
%macro SLEEP_SECONDS 1
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    sub rsp, 32                     ; space for timespec + alignment
    
    mov qword [rsp], %1             ; tv_sec = seconds
    mov qword [rsp + 8], 0          ; tv_nsec = 0
    
    mov rax, SYS_NANOSLEEP
    mov rdi, rsp                    ; pointer to timespec
    xor rsi, rsi                    ; remaining = NULL
    syscall
    
    add rsp, 32
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
%endmacro

; Sleep for specified number of milliseconds
; Args: milliseconds (immediate or register)
%macro SLEEP_MILLISECONDS 1
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    sub rsp, 32
    
    ; Convert milliseconds to seconds + nanoseconds
    mov rax, %1
    xor rdx, rdx
    mov rcx, MILLISECONDS_PER_SECOND
    div rcx                         ; rax = seconds, rdx = remaining ms
    
    mov [rsp], rax                  ; tv_sec = seconds
    
    imul rdx, NANOSECONDS_PER_MILLISECOND
    mov [rsp + 8], rdx              ; tv_nsec = remaining * 1000000
    
    mov rax, SYS_NANOSLEEP
    mov rdi, rsp
    xor rsi, rsi
    syscall
    
    add rsp, 32
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
%endmacro

; Sleep for specified number of nanoseconds
; Args: nanoseconds (immediate or register)
%macro SLEEP_NANOSECONDS 1
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    sub rsp, 32
    
    ; Convert nanoseconds to seconds + nanoseconds
    mov rax, %1
    xor rdx, rdx
    mov rcx, NANOSECONDS_PER_SECOND
    div rcx                         ; rax = seconds, rdx = remaining ns
    
    mov [rsp], rax                  ; tv_sec
    mov [rsp + 8], rdx              ; tv_nsec
    
    mov rax, SYS_NANOSLEEP
    mov rdi, rsp
    xor rsi, rsi
    syscall
    
    add rsp, 32
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
%endmacro

; Sleep using a timespec struct directly
; Args: pointer to timespec (sec at offset 0, nsec at offset 8)
%macro SLEEP_TIMESPEC 1
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    
    mov rax, SYS_NANOSLEEP
    mov rdi, %1                     ; pointer to timespec
    xor rsi, rsi                    ; remaining = NULL
    syscall
    
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
%endmacro

; Sleep with remaining time tracking (for interrupted sleep)
; Args: request timespec ptr, remaining timespec ptr
; Returns: 0 on success, -1 if interrupted (remaining updated)
%macro SLEEP_INTERRUPTIBLE 2
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    
    mov rax, SYS_NANOSLEEP
    mov rdi, %1                     ; request timespec
    mov rsi, %2                     ; remaining timespec
    syscall
    
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
%endmacro

; ============================================================================
; WAIT - Alias macros for more natural English
; ============================================================================

; Wait for N seconds (alias for SLEEP_SECONDS)
%macro WAIT_SECONDS 1
    SLEEP_SECONDS %1
%endmacro

; Wait for N milliseconds (alias for SLEEP_MILLISECONDS)
%macro WAIT_MILLISECONDS 1
    SLEEP_MILLISECONDS %1
%endmacro

; Wait for N nanoseconds (alias for SLEEP_NANOSECONDS)
%macro WAIT_NANOSECONDS 1
    SLEEP_NANOSECONDS %1
%endmacro

; ============================================================================
; ELAPSED TIME - Calculate duration between two timestamps
; ============================================================================

; Calculate elapsed seconds between two timestamps
; Args: start_time, end_time
; Returns: elapsed seconds in rax
%macro TIME_ELAPSED_SECONDS 2
    mov rax, %2
    sub rax, %1
%endmacro

; Calculate elapsed time between two timespecs (nanosecond precision)
; Args: start_timespec_ptr, end_timespec_ptr, result_timespec_ptr
; Result = end - start, stored in result
%macro TIME_ELAPSED_PRECISE 3
    push rbx
    push rcx
    push rdx
    
    ; Load end time
    mov rax, [%2 + TIMESPEC_SEC]
    mov rbx, [%2 + TIMESPEC_NSEC]
    
    ; Subtract start time
    sub rax, [%1 + TIMESPEC_SEC]
    sub rbx, [%1 + TIMESPEC_NSEC]
    
    ; Handle nanosecond underflow
    test rbx, rbx
    jns %%no_borrow
    add rbx, NANOSECONDS_PER_SECOND
    dec rax
%%no_borrow:
    
    ; Store result
    mov [%3 + TIMESPEC_SEC], rax
    mov [%3 + TIMESPEC_NSEC], rbx
    
    pop rdx
    pop rcx
    pop rbx
%endmacro

; ============================================================================
; TIMER - Stopwatch-style timer for measuring durations
; ============================================================================

; Initialize a timer struct (zeros all fields)
; Args: timer_ptr
%macro TIMER_INIT 1
    push rax
    push rdi
    push rcx
    
    mov rdi, %1
    xor rax, rax
    mov rcx, TIMER_SIZE / 8
%%zero_loop:
    mov [rdi], rax
    add rdi, 8
    dec rcx
    jnz %%zero_loop
    
    pop rcx
    pop rdi
    pop rax
%endmacro

; Start a timer (records start time)
; Args: timer_ptr
%macro TIMER_START 1
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    sub rsp, 16                     ; space for timespec
    
    mov r8, %1                      ; save timer ptr
    
    ; Get realtime for display purposes
    mov rax, SYS_TIME
    xor rdi, rdi
    syscall
    mov [r8 + TIMER_START_REAL], rax
    
    ; Get monotonic time for accurate duration
    mov rax, SYS_CLOCK_GETTIME
    mov rdi, CLOCK_MONOTONIC
    mov rsi, rsp
    syscall
    
    mov rax, [rsp]                  ; seconds
    mov rbx, [rsp + 8]              ; nanoseconds
    mov [r8 + TIMER_START_MONO_SEC], rax
    mov [r8 + TIMER_START_MONO_NSEC], rbx
    
    ; Mark as running
    mov qword [r8 + TIMER_RUNNING], 1
    
    add rsp, 16
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
%endmacro

; Stop a timer (records end time)
; Args: timer_ptr
%macro TIMER_STOP 1
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    sub rsp, 16
    
    mov r8, %1
    
    ; Get realtime
    mov rax, SYS_TIME
    xor rdi, rdi
    syscall
    mov [r8 + TIMER_END_REAL], rax
    
    ; Get monotonic time
    mov rax, SYS_CLOCK_GETTIME
    mov rdi, CLOCK_MONOTONIC
    mov rsi, rsp
    syscall
    
    mov rax, [rsp]
    mov rbx, [rsp + 8]
    mov [r8 + TIMER_END_MONO_SEC], rax
    mov [r8 + TIMER_END_MONO_NSEC], rbx
    
    ; Mark as stopped
    mov qword [r8 + TIMER_RUNNING], 0
    
    add rsp, 16
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
%endmacro

; Get timer duration in seconds (whole seconds only)
; Args: timer_ptr
; Returns: seconds in rax
%macro TIMER_DURATION_SECONDS 1
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    sub rsp, 16
    
    mov r8, %1
    
    ; Check if still running - if so, get current time
    cmp qword [r8 + TIMER_RUNNING], 1
    jne %%use_stored_end
    
    ; Get current monotonic time
    mov rax, SYS_CLOCK_GETTIME
    mov rdi, CLOCK_MONOTONIC
    mov rsi, rsp
    syscall
    
    mov rax, [rsp]                  ; current seconds
    sub rax, [r8 + TIMER_START_MONO_SEC]
    jmp %%done
    
%%use_stored_end:
    mov rax, [r8 + TIMER_END_MONO_SEC]
    sub rax, [r8 + TIMER_START_MONO_SEC]
    
%%done:
    add rsp, 16
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
%endmacro

; Get timer elapsed seconds (while running) - alias
%macro TIMER_ELAPSED_SECONDS 1
    TIMER_DURATION_SECONDS %1
%endmacro

; Get timer start time (unix timestamp)
; Args: timer_ptr
; Returns: unix timestamp in rax
%macro TIMER_START_TIME 1
    mov rax, [%1 + TIMER_START_REAL]
%endmacro

; Get timer end time (unix timestamp)
; Args: timer_ptr
; Returns: unix timestamp in rax
%macro TIMER_END_TIME 1
    mov rax, [%1 + TIMER_END_REAL]
%endmacro

; ============================================================================
; DATETIME - Extract date/time components from unix timestamp
; ============================================================================

; Convert unix timestamp to datetime struct
; Args: unix_timestamp, datetime_ptr
; Fills: year, month, day, hour, minute, second
%macro UNIX_TO_DATETIME 2
    ; Capture parameters BEFORE pushes (in case %1 or %2 use rsp)
    mov rax, %1                     ; unix timestamp
    mov r12, %2                     ; datetime ptr
    
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12                        ; save r12 (datetime ptr) on stack
    
    ; Store original unix time
    mov [r12 + DATETIME_UNIX], rax
    
    ; Calculate seconds of day
    xor rdx, rdx
    mov rcx, SECONDS_PER_DAY
    div rcx                         ; rax = days since epoch, rdx = seconds today
    
    mov r8, rax                     ; r8 = total days
    mov r9, rdx                     ; r9 = seconds today
    
    ; Extract hour, minute, second from seconds today
    mov rax, r9
    xor rdx, rdx
    mov rcx, SECONDS_PER_HOUR
    div rcx                         ; rax = hours, rdx = remaining
    mov [r12 + DATETIME_HOUR], rax
    
    mov rax, rdx
    xor rdx, rdx
    mov rcx, SECONDS_PER_MINUTE
    div rcx                         ; rax = minutes, rdx = seconds
    mov [r12 + DATETIME_MINUTE], rax
    mov [r12 + DATETIME_SECOND], rdx
    
    ; Calculate year from days
    mov rax, EPOCH_YEAR             ; start year
    mov r10, r8                     ; remaining days
    
%%year_loop:
    ; Check if leap year: divisible by 4, not by 100, or by 400
    mov rcx, rax
    push rax
    
    ; Check div by 4
    mov rax, rcx
    xor rdx, rdx
    mov rbx, 4
    div rbx
    test rdx, rdx
    jnz %%not_leap
    
    ; Check div by 100
    mov rax, rcx
    xor rdx, rdx
    mov rbx, 100
    div rbx
    test rdx, rdx
    jnz %%is_leap
    
    ; Check div by 400
    mov rax, rcx
    xor rdx, rdx
    mov rbx, 400
    div rbx
    test rdx, rdx
    jnz %%not_leap
    
%%is_leap:
    mov r11, DAYS_PER_LEAP_YEAR
    jmp %%check_year
    
%%not_leap:
    mov r11, DAYS_PER_YEAR
    
%%check_year:
    pop rax
    cmp r10, r11
    jl %%year_done
    
    sub r10, r11
    inc rax
    jmp %%year_loop
    
%%year_done:
    mov [r12 + DATETIME_YEAR], rax
    
    ; r10 now has day of year (0-based)
    ; Calculate month and day
    
    ; Check if current year is leap
    mov rcx, rax
    xor r11, r11                    ; r11 = leap flag
    
    mov rax, rcx
    xor rdx, rdx
    mov rbx, 4
    div rbx
    test rdx, rdx
    jnz %%year_not_leap
    
    mov rax, rcx
    xor rdx, rdx
    mov rbx, 100
    div rbx
    test rdx, rdx
    jnz %%year_is_leap
    
    mov rax, rcx
    xor rdx, rdx
    mov rbx, 400
    div rbx
    test rdx, rdx
    jnz %%year_not_leap
    
%%year_is_leap:
    mov r11, 1
    
%%year_not_leap:
    ; Iterate through months
    xor rcx, rcx                    ; month counter (0-based)
    lea rsi, [_days_in_month]
    
%%month_loop:
    xor rax, rax
    mov al, [rsi + rcx]             ; days in this month
    
    ; February in leap year
    cmp rcx, 1
    jne %%not_feb
    test r11, r11
    jz %%not_feb
    inc rax                         ; 29 days in Feb
%%not_feb:
    
    cmp r10, rax
    jl %%month_done
    
    sub r10, rax
    inc rcx
    cmp rcx, 12
    jl %%month_loop
    
%%month_done:
    inc rcx                         ; 1-based month
    mov [r12 + DATETIME_MONTH], rcx
    
    inc r10                         ; 1-based day
    mov [r12 + DATETIME_DAY], r10
    
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
%endmacro

; Get current time as datetime struct
; Args: datetime_ptr
%macro DATETIME_NOW 1
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    
    ; Get current unix time
    mov rax, SYS_TIME
    xor rdi, rdi
    syscall
    
    ; Convert to datetime
    mov rdi, %1
    UNIX_TO_DATETIME rax, rdi
    
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
%endmacro

; Extract individual components from unix timestamp
; Returns value in rax

%macro TIME_GET_HOUR 1
    push rbx
    push rcx
    push rdx
    sub rsp, DATETIME_SIZE
    
    UNIX_TO_DATETIME %1, rsp
    mov rax, [rsp + DATETIME_HOUR]
    
    add rsp, DATETIME_SIZE
    pop rdx
    pop rcx
    pop rbx
%endmacro

%macro TIME_GET_MINUTE 1
    push rbx
    push rcx
    push rdx
    sub rsp, DATETIME_SIZE
    
    UNIX_TO_DATETIME %1, rsp
    mov rax, [rsp + DATETIME_MINUTE]
    
    add rsp, DATETIME_SIZE
    pop rdx
    pop rcx
    pop rbx
%endmacro

%macro TIME_GET_SECOND 1
    push rbx
    push rcx
    push rdx
    sub rsp, DATETIME_SIZE
    
    UNIX_TO_DATETIME %1, rsp
    mov rax, [rsp + DATETIME_SECOND]
    
    add rsp, DATETIME_SIZE
    pop rdx
    pop rcx
    pop rbx
%endmacro

%macro TIME_GET_DAY 1
    push rbx
    push rcx
    push rdx
    sub rsp, DATETIME_SIZE
    
    UNIX_TO_DATETIME %1, rsp
    mov rax, [rsp + DATETIME_DAY]
    
    add rsp, DATETIME_SIZE
    pop rdx
    pop rcx
    pop rbx
%endmacro

%macro TIME_GET_MONTH 1
    push rbx
    push rcx
    push rdx
    sub rsp, DATETIME_SIZE
    
    UNIX_TO_DATETIME %1, rsp
    mov rax, [rsp + DATETIME_MONTH]
    
    add rsp, DATETIME_SIZE
    pop rdx
    pop rcx
    pop rbx
%endmacro

%macro TIME_GET_YEAR 1
    push rbx
    push rcx
    push rdx
    sub rsp, DATETIME_SIZE
    
    UNIX_TO_DATETIME %1, rsp
    mov rax, [rsp + DATETIME_YEAR]
    
    add rsp, DATETIME_SIZE
    pop rdx
    pop rcx
    pop rbx
%endmacro
