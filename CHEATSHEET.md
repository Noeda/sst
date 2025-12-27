# SST cheatsheet

```bash
$ sst option1 option2 optionN -- command arg1 arg2 argN
```

## Sandboxing enable options

- `ENABLE_FILESYSTEM_SANDBOXING`
- `ENABLE_NETWORK_SANDBOXING`

## Filesystem

- `FILE_READ:<filepath>`
- `FILE_EXEC:<filepath>`
- `FILE_WRITE:<filepath>`
- `FILE_EXEC_WRITE:<filepath>`
- `FILE_WRITE_EXEC:<filepath>` [1]
- `PATH_BENEATH_READ:<dir>`
- `PATH_BENEATH_EXEC:<dir>`
- `PATH_BENEATH_WRITE:<dir>`
- `PATH_BENEATH_EXEC_WRITE:<dir>`
- `PATH_BENEATH_WRITE_EXEC:<dir>` [1]

`FILE` must be used with regular files. `PATH_BENEATH` must be used with directories.

[1] `WRITE_EXEC` is alias for `EXEC_WRITE`

## Networking

- `ALLOW_INCOMING_TCP_PORT:<port>`
- `ALLOW_OUTGOING_TCP_PORT:<port>`

