# Simple sandboxer tool

`sst` (Simple sandboxer tool) is a small CLI tool that will run some other
program while under some sandboxing, using Linux Landlock API.

It is implemented in a single, free-standing `sst.c` file with no dependencies beyond having
a C compiler available.

`sst` does not need root or any privileges itself; courtesy of Linux Landlock being
designed to be usable from a position of unprivileged usercode.

If you know what is bubblewrap and `bwrap`, then this program is similar except
it is purely and only focused on Linux Landlock-provided features.

## Compiling

If you have a Linux machine with development tools, then `make` hopefully
suffices. It will compile `sst` to the current directory.

```console
$ make
$ ./sst <options here>
```

`sst.c` is, on purpose, a single file with no dependencies other than Kernel headers, so you could also try:

```console
$ gcc -Wall -O2 sst.c -o sst
$ ./sst <options here>
```

## Usage

The command line tool is called `sst` (for "Simple Sandboxer Tool"). By default, it will
not restrict anything.

```console
$ sst <options...> -- <command> <arg1> <arg2> ... <argN>
```

Note: The `--` is mandatory. You specify on the command line, before the `--`, how do you want to sandbox.

The ordering of the options before `--` does not matter.

You can nest `sst` calls, e.g. one only does filesystem sandboxing, and another
does networking sandboxing. The permissions can only be tightened; an `sst`
cannot increase privileges under Landlock.

### Examples

Open a shell that can't do (TCP) networking:

```console
$ sst ENABLE_NETWORK_SANDBOXING -- bash
$ nc -v example.org 80
Warning: inverse host lookup failed for 104.18.3.24:
Warning: inverse host lookup failed for 104.18.2.24:
example.org [104.18.3.24] 80 (http) : Permission denied
```

(note: some programs may know HTTP3/QUIC which uses UDP instead, as mentioned
elsewhere in this `README.md`. They would still work.).

Run a program with a read-only root and some directories with write permission:

```console
$ sst ENABLE_FILESYSTEM_SANDBOXING PATH_BENEATH_EXEC:/ PATH_BENEATH_WRITE:/workspace/my_program -- my_program --option 123
```

#### Lazy template to use

This is often my starting point when I design a sandboxer for some program.

This stops networking and stops filesystem write access entirely. The root is set to `PATH_BENEATH_EXEC` which lets the opened `bash` shell to execute and run commands; but none of these commands can leave a mark on the filesystem.

```console
$ sst ENABLE_FILESYSTEM_SANDBOXING ENABLE_NETWORK_SANDBOXING PATH_BENEATH_EXEC:/ -- bash
```

Remove `ENABLE_NETWORK_SANDBOXING` if you would like to allow Internet (or fine-tune that with the networing-related sandboxing options).

Add `PATH_BENEATH_WRITE:<directory>` as needed to allow selectively write access to some parts of the filesystem.

## Sandboxing

You might be interested in CHEATSHEET.md in this repository for an uncluttered "cheat sheet" version of this information.

### Filesystem-related sandboxing

To use any options below, you must specify, somewhere, on the command line,
before the `--` separator, the trigger option word `ENABLE_FILESYSTEM_SANDBOXING`. This
enables the use of the options below, and it also restricts all filesystem access except
the ones specified.

- `FILE_READ:<path>`: allow reading from a specific file. The file has to be an actual file, not a directory. Executing the file is not allowed.
- `FILE_EXEC:<path>`: same as `FILE_READ` but adds execution privileges.
- `FILE_WRITE:<path>`: same as `FILE_READ` but adds write privileges (not execution privileges).
- `FILE_EXEC_WRITE:<path>`: combined `FILE_EXEC` and `FILE_WRITE` (you can also separately specify them).
- `FILE_WRITE_EXEC:<path>`: alias for `FILE_EXEC_WRITE`.
- `PATH_BENEATH_READ:<path>`: allow reading (not executing) everything under `<path>`. The path must refer to a directory.
- `PATH_BENEATH_EXEC:<path>`: same as `PATH_BENEATH_READ` but also gives execution privileges.
- `PATH_BENEATH_WRITE:<path>`: same as `PATH_BENEATH_READ` but also gives write privileges.
- `PATH_BENEATH_EXEC_WRITE:<path>`: combined `PATH_BENEATH_EXEC` and `PATH_BENEATH_WRITE` (you can also separately specify them).
- `PATH_BENEATH_WRITE_EXEC:<path>`: alias for `PATH_BENEATH_EXEC_WRITE`.

### Networking-related sandboxing

To use any options below, you must specify, somewhere, on the command line,
before the `--` separator, the trigger option word `ENABLE_NETWORK_SANDBOXING`. This
enables the other options, and it also restricts all TCP networking except the ones specified.

Note: this does not restrict other forms of network communications (e.g. UDP).
QUIC for example is UDP, so this tool cannot block it. (try `curl https://google.com/` while sandboxing networking;
a modern enough curl will use UDP!).

As of writing of this: ABI 8 of Landlock API looks like UDP support is coming.

- `ALLOW_INCOMING_TCP_PORT:<port>`: allow incoming connections to the given port. 0 can be specified, read `bind()` documentation on what does binding to port 0 mean exactly.
- `ALLOW_OUTGOING_TCP_PORT:<port>`: allow outgoing connections to the given port.

## Warts, issues, thoughts

### Scope of Landlock and intended use

Landlock at least in its current form is not a foolproof sandboxing system;
look for other technologies (e.g. bubblewrap, firejail on Linux; App Sandboxing
on MacOS; and use actual firewalls to stop networking) if you are working with
code you expect to be actively adversarial that makes an effort to work around
the sandbox. I consider `sst` to be the "quick & lazy sandboxing method that I
can just slap on things, bam done" route, and I escalate to more thorough
methods depending on what am I dealing with.

Here are some use cases I've used this for so far:

  1) stop unwanted telemetry (my original motivation; in late 2025 I touched a JavaScript framework with some particularly facetious attitude about telemetry and got annoyed :-)
  2) sandbox my own applications. I especially do this with software that I have to deal with and that is exposed to the Internet; e.g. Minecraft servers, <insert your latest 21st century Web/JavaScript thingamajig framework>-based applications.

I consider this to be, at best, one layer of defense, and I think at the moment
this only is effective because most software I target with this are not
expecting to be sandboxed (i.e. software by unscrupulous tech companies filled
with telemetry or some other user-hostile code), or they are not hostile
programs to begin with.

Future improvements to this script might be about adding features to help with
*observability* rather than sandboxing. Landlock itself has some amount of
"audit features" but I have not studied them as of writing this section right
now, or if it makes sense to put such features into this script specifically.

### Filesystem sandboxing may be overly restrictive.

The filesystem restrictions restrict a lot of operations; the most permissive
setting you can set (while also having filesystem sandboxing on at all) is this combo:

```c
static const __u32 EXEC_WRITE_FILE_ACCESS =
    LANDLOCK_ACCESS_FS_EXECUTE |
    LANDLOCK_ACCESS_FS_READ_FILE |
    LANDLOCK_ACCESS_FS_READ_DIR |
    LANDLOCK_ACCESS_FS_WRITE_FILE |
    LANDLOCK_ACCESS_FS_TRUNCATE;
```

There are a lot more filesystem flags within Landlock, but they are not exposed
through `sst`. The current set of options you can set reflect my own use of this tool, but I will
expand and improve over time if I find a good design for it.

Non-TCP networking is not blocked at all (e.g. UDP, used in HTTP3/QUIC). I will likely add it
as soon as my system gets updated enough to have it in the installed Kernel headers and I am
able to test it conveniently. One of the use cases of this sandboxing is to stop unwanted telemetry,
but if the telemetry uses UDP it kind of defeats the point of sandboxing.

## License

GPL3 only.
