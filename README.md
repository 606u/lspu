# lspu

`lspu` is a command-line FreeBSD utility to list running processes currently using given binaries or shared libraries, because this information is not available via `fstat`.

For example, it might help finding out how many processes will be affected when upgrading a shared library.


## Usage

Run it with full paths to binaries or shared libraries. For example, `lspu /lib/libc.so.7` will list pretty much every non-jailed running user process.

One can also use `procstat -va | grep /lib/libc.so.7`, but `procstat` omits process name/path.

Exit codes are

  * `0` if no processes found,
  * `1` on error of some sort,
  * `2` if one or more processes are found.


## Compilation

Just type `make`.


## Test

`Makefile` contains few "test" targets, for example

    # make test2
    ./lspu /lib/libcam.so.6
       pid    jid command
       815      0 /usr/local/sbin/smartd
    *** Error code 2

`make` fails, because, on my machine, `lspu` returns `2`, as smartmontools are using `/lib/libcam.so.6`.


## Limitations

It will omit listing processes if binaries or shared libraries are already deleted or replaced; [lsop] might help you there.

[lsop]: https://github.com/606u/lsop "lsop - lists processes running with outdated binaries or shared libraries"
