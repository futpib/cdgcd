# cdgcd

> Allow-list garbage collector for systemd-coredump dumps

`systemd-coredump` itself has no per-process filter — its cleanup is
purely age-based (`systemd-tmpfiles`, default 3 days) and size-based
(`MaxUse=`). Neither understands "keep dumps for `myapp`, drop everything
else."

cdgcd is a long-lived daemon that watches `/var/lib/systemd/coredump/`
via inotify and applies a rule-based allow-list with optional per-rule
quotas. It complements `MaxUse=` and `tmpfiles`; it does not replace
them.

## Install

Arch Linux: https://aur.archlinux.org/packages/cdgcd-git

From source:

```bash
cargo install --path .
```

Then drop the unit and example config in place:

```bash
sudo install -m 644 etc/cdgcd.service /etc/systemd/system/
sudo install -m 644 etc/cdgcd.toml    /etc/cdgcd.toml
sudo systemctl enable --now cdgcd
```

## Config

`/etc/cdgcd.toml`. Each `[rules.<name>]` is a match; first match wins
in source order; an unmatched dump is unlinked. Within a field, items
are OR; fields combine with AND.

`[rules.DEFAULT]` is special: its fields are merged as defaults into
every named rule, and DEFAULT itself is evaluated as the LAST rule
— a catch-all so the daemon is runnable with just DEFAULT defined.

```toml
[rules.DEFAULT]
group_by   = ["process_name"]   # bucket the cap below per comm
keep_count = 3                  # inherited by every rule, and the catch-all itself

[rules.firefox]
process_name = ["firefox", "firefox-bin"]
keep_count   = 10               # overrides DEFAULT's 3 for firefox

[rules.workers]
executable_path = ["/opt/workers/*"]
group_by        = ["executable_path"]   # bucket per distinct exe path
keep_count      = 5
```

Available rule fields:

| field             | source       | notes                                           |
| ----------------- | ------------ | ----------------------------------------------- |
| `process_name`    | filename     | kernel `comm`, max 15 bytes (see below)         |
| `executable_path` | journal      | full path to the binary                         |
| `command_line`    | journal      | full cmdline                                    |
| `signal`          | journal      | signal name, e.g. `"SIGSEGV"`                   |
| `user_id`         | filename     | numeric uid                                     |
| `user_name`       | passwd       | resolved to uid at config load                  |
| `group_by`        | —            | bucket `keep_count` by tuple of these fields    |
| `keep_count`      | —            | keep N newest per bucket (or per rule if no group_by) |

`process_name` matches the kernel's `comm` field. The kernel allocates
`TASK_COMM_LEN` (16) bytes for it in `task_struct` (see
`include/linux/sched.h`); one byte is reserved for the trailing NUL,
so what `/proc/PID/comm` (and therefore the systemd-coredump filename)
actually exposes is at most 15 bytes. A `process_name` glob whose
literal portion already exceeds 15 bytes can never match — cdgcd
refuses such patterns at config load rather than silently never
firing.

Top-level fields: `coredump_directory`, `idle_interval`, `minimum_age`,
`dry_run`. Defaults are sensible; see `etc/cdgcd.toml`.

## Pinning a dump for triage

```bash
cdgcctl retain                  # pin the most recent dump
cdgcctl retain core.foo.0...zst # pin a specific one
```

This touches `<dump>.cdgc-retain` next to the dump. Pinned dumps are
never deleted by cdgcd and don't count against any rule's `keep_count`.
The dump dir is root-owned, so on EACCES `cdgcctl` prints both
`sudo cdgcctl retain ...` and `sudo touch ...` hints.

## systemd-coredump tuning

`MaxUse=` is the disk-pressure safety net; cdgcd does the policy work.
If `MaxUse=` is tighter than what your rules want to keep, MaxUse will
evict the dumps you wanted before cdgcd notices. Set it well above your
normal workload:

```ini
# /etc/systemd/coredump.conf
[Coredump]
Storage=external                # required — cdgcd can't manage Storage=journal
Compress=yes
MaxUse=8G
ProcessSizeMax=infinity
ExternalSizeMax=infinity
```

`systemd-tmpfiles-clean.timer` still deletes anything older than 3 days
by default. If you want retention past that — including `cdgcctl retain`
pins surviving longer than 3 days — override the rule by writing to
`/etc/tmpfiles.d/systemd.conf`:

```
d /var/lib/systemd/coredump 0755 root root -
```

If you only care about dumps within the last 3 days, you can leave it
and cdgcd just becomes a within-3-days quota manager.

## Debug or test your config

```bash
cdgcd --configuration-file ./cdgcd.toml check    # print decisions, no action
cdgcd --configuration-file ./cdgcd.toml scan     # one-shot, exits non-zero on deletes
RUST_LOG=debug cdgcd --configuration-file ./cdgcd.toml run
```

`SIGHUP` reloads config; `SIGUSR1` triggers a scan immediately.

## See also

* [`coredumpctl`](https://man7.org/linux/man-pages/man1/coredumpctl.1.html) — list, inspect, debug captured dumps
* [`coredump.conf`](https://www.freedesktop.org/software/systemd/man/latest/coredump.conf.html) — `Storage=`, `MaxUse=`, etc.
* [choomd](https://github.com/futpib/choomd) — sibling daemon for OOM-killer score adjustment

## What does the name mean?

Coredump GC daemon. CD-GC-D.
