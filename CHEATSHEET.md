# SST cheatsheet

```bash
$ sst option1 option2 optionN -- command arg1 arg2 argN
```

## Filesystem

- `FILE_READ:<path>`
- `FILE_EXEC:<path>`
- `FILE_WRITE:<path>`
- `FILE_EXEC_WRITE:<path>`
- `FILE_WRITE_EXEC:<path>` [1]
- `PATH_BENEATH_READ:<path>`
- `PATH_BENEATH_EXEC:<path>`
- `PATH_BENEATH_WRITE:<path>`
- `PATH_BENEATH_EXEC_WRITE:<path>`
- `PATH_BENEATH_WRITE_EXEC:<path>` [1]

`FILE` refers to regular files. `PATH_BENEATH` must be used with directories.

[1] `WRITE_EXEC` is alias for `EXEC_WRITE`

## Networking

- `ALLOW_INCOMING_TCP_PORT:<port>`
- `ALLOW_OUTGOING_TCP_PORT:<port>`

