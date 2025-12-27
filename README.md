# Simple sandboxer tool

This is a small CLI tool that will run some other programs while under some
sandboxing, using Linux Landlock API.

This does not need root or any privileges itself; courtesy of Linux Landlock being
designed to be usable from a position of unprivileged usercode.

