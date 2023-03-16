
# mevi

A memory visualizer for Linux 5.7+

Made for this video: (FILL ME)

## Prerequisite

The `vm.unprivileged_userfaultfd` sysctl needs to be switched to 1:

```shell
$ sudo sysctl -w vm.unprivileged_userfaultfd=1
```

Doing this effectively "softens" your system to some attacks, so only do this in
a VM or if you're reckless, but also, it seems less awful than running mevi +
tracees as root. (No, giving the `mevi` binary CAP_PTRACE isn't enough).

You can _technically_ run a bunch of apps with only user faults, but some fairly
basic stuff like `cat /hosts` will fail with EFAULT without it, so, I'm not
making it easy to go that route - if you _really_ know what you're doing you can
figure out where to pass the "user faults only" flag.

## Usage

Install the `mevi` executable:

```shell
$ just install
```

(Or, without [just](https://github.com/casey/just), look into the `Justfile` for
the cargo invocation)

Build & serve the frontend (you'll need [trunk](https://trunkrs.dev/)):

```shell
$ just serve
```

Open the frontend in your browser: <http://localhost:8080>

From another terminal, start the program you want to trace via mevi:

```shell
$ mevi PROGRAM ARGS
```

The frontend should connect to `http://localhost:5001/stream`.

If you're running this on a remote server, you'll need to forward both ports, with SSH for example:

```shell
ssh -L 5001:localhost:5001 -L 8080:localhost:8080 your-remote-host
```

## License

This project is primarily distributed under the terms of both the MIT license
and the Apache License (Version 2.0).

See [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT) for details.

## FAQ / Troubleshooting

### I get `EPERM` at some point

Did you skip past that `sysctl` note above?

### The RSS numbers don't match up with htop/btop/procmaps etc.

mevi only tracks private+anonymous memory mappings. The discrepancy probably
comes from mapped files, and to a lesser extent, shared memory.

### I have a tiny program and everything goes by way too fast.

Try sleeping in your loops! Computers go fast noawadays and mevi _tries_ not to
slow your program down.

### I have a multi-threaded program and it's all wrong

Yeah, sorry about that. userfaultfd events don't have all the info we need, and
ptrace observes events out-of-order, so the view of multi-threaded programs
gets out-of-sync with the kernel.

### Can I run this on a big program?

Sure, Firefox works, with a non-snap version, and with sandbox disabled, like
so (THIS IS DANGEROUS, THE SANDBOX IS THERE FOR A REASON).

First let's make sure you don't have firefox running in the background:

```shell
$ pkill firefox
# you can do it several times, until `pidof firefox` returns nothing
```

Then:

```shell
$ RUST_LOG=error RUST_BACKTRACE=1 MOZ_DISABLE_CONTENT_SANDBOX=1 MOZ_DISABLE_GMP_SANDBOX=1 MOZ_DISABLE_RDD_SANDBOX=1 MOZ_DISABLE_SOCKET_PROCESS_SANDBOX=1 mevi /usr/lib/firefox/firefox
```

### Does this show backtraces?

No, but you can do that in your fork.

### Does this allow travelling back in time?

No, but you can do that in your fork.

### Does this have yet another, secret third feature?

Clearly not, but again, you can do that in your fork. This is a research
project, I will not be maintaining it beyond "have it run in its current form".

If you want to spin this out into its own product, more power to you, but I'll
have already moved on.

### Why isn't this published on crates.io?

It's not a library and it's not usable without the frontend anyway. One day
stable cargo will let us build wasm artifacts and ship them with the resulting
binary, but that day is not today.

### Why isn't this using eBPF?

I wanted to see how far I could take ptrace + userfaultfd. I'm interested in
exploring eBPF later.
