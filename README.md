
# mevi3

A memory visualizer.

## kernel userfaultfd support

Needs that sysctl to be switched to 1:

```shell
$ sudo sysctl -w vm.unprivileged_userfaultfd=1
```

Alternatively, a bunch of apps still work without it, change
`.user_mode_only(false)` to `true` in `mevi-preload`.
