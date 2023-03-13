
# mevi3

A memory visualizer.

## userfaultfd non-user-mode support (kernel faults)

Needs that sysctl to be switched to 1:

```shell
$ sudo sysctl -w vm.unprivileged_userfaultfd=1
```

Alternatively, a bunch of apps still work without it, change
`.user_mode_only(false)` to `true` in `mevi-preload`.

## userfaultfd EVENT_FORK support

You'd think `sudo setcap cap_sys_ptrace=ep target/release/mevi` would do the
job, but no, since the uffd is initialized from child processes, which _do not_
have `CAP_SYS_PTRACE`, so the only solution is to run stuff as root.

## Running electron as root

It fails to load GUI-related stuff unless you let your X server accept
connections from other users apparently:

```shell
$ xhost + local:
```

## strace notes

`mevi-preload` does this:

```
userfaultfd(0)                          = 3

ioctl(3, UFFDIO_API, {api=0xaa, features=UFFD_FEATURE_EVENT_REMAP|UFFD_FEATURE_EVENT_REMOVE|UFFD_FEATURE_EVENT_UNMAP => features=UFFD_FEATURE_PAGEFAULT_FLAG_WP|UFFD_FEATURE_EVENT_FORK|UFFD_FEATURE_EVENT_REMAP|UFFD_FEATURE_EVENT_REMOVE|UFFD_FEATURE_MISSING_HUGETLBFS|UFFD_FEATURE_MISSING_SHMEM|UFFD_FEATURE_EVENT_UNMAP|UFFD_FEATURE_SIGBUS|UFFD_FEATURE_THREAD_ID|UFFD_FEATURE_MINOR_HUGETLBFS|UFFD_FEATURE_MINOR_SHMEM|0x1800, ioctls=1<<_UFFDIO_REGISTER|1<<_UFFDIO_UNREGISTER|1<<_UFFDIO_API}) = 0
ioctl(0x3, 0xc018aa3f, 0x7ffd5ac8d618)  = 0

socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0) = 4
socket(0x1, 0x80001, 0)                 = 0x4

connect(4, {sa_family=AF_UNIX, sun_path="/tmp/mevi.sock"}, 17) = 0
connect(0x4, 0x7ffe63e7f5f8, 0x11)      = 0

getpid()                                = 2970738
getpid()                                = 0x2d53ff

write(4, "\0\0\0\0\0-Tr", 8)            = 8
write(0x4, 0x7ffe63e7f758, 0x8)         = 0x8

sendmsg(4, {msg_name=NULL, msg_namelen=0, msg_iov=[{iov_base="\0\0\0\0", iov_len=4}], msg_iovlen=1, msg_control=[{cmsg_len=20, cmsg_level=SOL_SOCKET, cmsg_type=SCM_RIGHTS, cmsg_data=[3]}], msg_controllen=24, msg_flags=0}, 0) = 4
sendmsg(0x4, 0x7ffe63e7f5a0, 0)         = 0x4

close(4)                                = 0
close(0x4)                              = 0
```
