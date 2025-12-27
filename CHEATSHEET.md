# SST cheatsheet

```bash
$ sst option1 option2 optionN -- command arg1 arg2 argN
```

## Sandboxing enable options

- `ENABLE_FILESYSTEM_SANDBOXING`
- `ENABLE_NETWORK_SANDBOXING`

## Filesystem

- `FILE_READ:<filepath>` [1]
- `FILE_EXEC:<filepath>`
- `FILE_WRITE:<filepath>`
- `FILE_EXEC_WRITE:<filepath>`
- `FILE_WRITE_EXEC:<filepath>` [2]
- `PATH_BENEATH_READ:<dir>` [1]
- `PATH_BENEATH_EXEC:<dir>`
- `PATH_BENEATH_WRITE:<dir>`
- `PATH_BENEATH_EXEC_WRITE:<dir>`
- `PATH_BENEATH_WRITE_EXEC:<dir>` [2]

`FILE` must be used with 'file-like' files (currently this means: regular
files, block devices or character devices). `PATH_BENEATH` must be used with
directories.

[1] `EXEC` and `WRITE` also sets the `READ` permission.

[2] `WRITE_EXEC` is alias for `EXEC_WRITE`

## Networking

- `ALLOW_INCOMING_TCP_PORT:<port>`
- `ALLOW_OUTGOING_TCP_PORT:<port>`

