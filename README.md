# Theseus
Theseus replaces your operating system one file at a time.

Theseus consists of two components: `theseus`, the wizard (or client) component, and `theseusd` the daemon (or server) component.

## `theseus`
`theseus` is the wizard component of Theseus.
The wizard supports multiple commands, some of which operate on local data (`validate`) and some of which only operate on remote data (`upload`, `apply`).

### Commands
`theseus` has three subcommands: `validate`, `upload`, and `apply`.

`validate` checks that a plan is in the proper form to be `upload`-ed and `apply`-ed to and by a daemon.

`upload` uploads a plan to a daemon.
If the daemon already has that plan, the wizard does not upload it again.

`apply` commands a daemon to execute a plan.


## `theseusd`
`theseusd` is the daemon component of Theseus.
Almost all of the time the daemon lies idle, until a wizard sends it a command.
The daemon will try to execute the command, but may fail in the middle for any number of reasons.
If that happens, the daemon will attempt to reset the system back to the state it was in before the command was partially executed.
The execute/unwind logic is implemented in `src/plan.rs`, and execution for a `FileTarget` plan (the only type currently supported) is in `src/target.rs`

### Commands
`theseusd` has two subcommands: `validate`, and `run`.

`validate` reads a config file and tries to ensure that it is valid.
This involves parsing the configuration, but also verifying that several directories used to store daemon state exist and are correctly permissioned.
`validate`-ing a config file results in modification to the file system.

`run` reads a config file, and listens for commands from a wizard.

## Security
While `theseusd` does not directly execute code on behalf of a user, it does manage files on the system.
Additionally, `theseusd` speaks raw TCP and does not support any form of authentication, or even transport encryption.
This makes systems running `theseusd` extremely vulnerable if it is run on a network interface accessible by adversaries.
A recommended way around this is to use a SDN with powerful ACLs to require authentication to talk to the `theseusd` interface/port.
The author uses and recommends Tailscale for this purpose, but many such solutions are available.

`theseusd` needs to run with enough privileges to manage any file a wizard asks it to.
Generally, this means it needs to run with `root` privileges.
At this time, `theseusd` does not support internal privilege escalation, nor does it fork a new process or thread to handle incoming connections.
However, `theseusd` is written in Rust and is believed to be free of internal memory safety, privilege escalation vulnerabilies.


## Copying
Theseus is distributed under the Apache License, Version 2.0 
