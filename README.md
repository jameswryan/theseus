# Theseus
Theseus replaces your operating system one file at a time.

Theseus consists of two components: `theseus`, the wizard (or client) component, and `theseusg` the golem (or server) component.

## `theseus`
`theseus` is the wizard component of Theseus.
The wizard has some local commands (`help`, `list-golems`, `validate`), and some remote commands (`construct-golem`, `apply`).
Local commands operate only on your local machine, while remote commands will connect to a remote machine and construct a golem.


## `theseusg`
`theseusg` is the golem component of Theseus.
It is not intended to be run interactively, but only by a wizard.

## Golems
Theseus works by uploading a 'golem' binary to a target machine, and then sending it some instructions to carry out.
Since the golem is written in rust, it must be compiled for that machine.
If your target machine is running Linux, you can probably use a golem compiled for the `musl` C library, as it can be statically linked by `rustc`.
For other targets, you'll likely need to compile a golem yourself on a similar machine.
In the future, we may provide precompiled golems for some platforms.


## Getting started
First, create a plan.

A plan is a tree of files and directories, along with metadata about the files, such as owner, group, and UNIX permissions.
The filesyetem structure of your plan should match that of the machine you would like to apply the plan to.
So if you want the file `/etc/ssh/sshd_config` to be in the plan it should look like:
```
.
└── etc
    └── ssh
        └── sshd_config
```

Theseus plans store the metadata in the filename to allow all files to be editable on the wizard's local machine.
So if the file metadata in the example above should be `owner: root, group: wheel, permissions: 644`, the file name should be `sshd_config:root:wheel:644`.

A plan with multiple such files might look like:
```
.
├── etc
│   ├── rc.conf
│   ├── rc.conf:root:wheel:644
│   └── ssh
│       └── sshd_config:root:wheel:644
└── usr
    └── local
        └── etc
            ├── doas.conf:root:wheel:644
            └── smb4.conf:root:wheel:644
```

Next, you'll need passwordless ssh access to the machine you would like to apply the plan to.
The golem does not support escalating privileges, so you'll probably need passwordless access to the root user.

Check that your plan is valid with `theseus validate </path/to/your/plan>`, and apply it to the target machine with `theseus apply -a <ip address or hostname> -d </path/to/your/plan>`.


## Copying
Theseus is distributed under the Apache License, Version 2.0 
