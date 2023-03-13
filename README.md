
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
