Welcome to breakzip! This is a collection of open source utilities for working
with Zip files and cracking (hopefully) their encryption key. This project is
written and maintained by:

*  Mike Stay <stay@pyrofex.net>
*  Nash Foster <leaf@pyrofex.net>

The project was generously funded by Sergey Tolmachev Tolsi, to whom we owe
many thanks for the opportunity to work on this project.


# BUILD

This project was developed on Ubuntu 19, but is known to build on Unbuntu 18.
Patches to support other distribution version will be accepted, but the authors
do not intend to provide explicit support for general portability. Your mileage
may vary.

## Dependencies

* `autotools-dev`
* `automake`
* `cmake` >= 13.0
* `build-essential`
* `debian-keyring`
* `doxygen`
* `g++-6-multilib`
* `g++-multilib`
* NVIDIA's CUDA Toolkit v10.2 or later
* `libgflags-dev`
* `libgoogle-perftools-dev` (for `tcmalloc`)
* `libstdc++6-6-dbg:amd64`
* `pkg-config`
* `texinfo`

## Anti-dependencies

* `libsubunit`

We don't know why `libsubunit` causes compile errors, but it does. Remove it from
your system before proceeding. If you figure out why it's breaking and can fix it
for us, that would be nice.

## Third-party

Some dependencies are distributed as source code in our `third-party` directory.
On Ubuntu machines, you should not have to build any dependencies from source.
Everything that's not distributed as a working Ubuntu package is included in
`third-party` for you and build by CMake.

This project is not tested using `clang`, but it may work. You're on your own,
but if you make it work, send us a merge request.

## Building the Project

Once your system has the needed dependencies, you can build the project by simply
running the following command in the root directory.

```
bash$ ./build.sh
```

This will produce a build in `build.out`, including a `deb` package suitable for
installation on your operating system. You can either run the utilities directly
from `build.out` or you can install the deb package with:

```
bash$ dpkg -i build.out/breakzip-*-Linux.deb
```

There is also a `clean.sh` script that can be used to clean the build directories.

If you need to build a debug version, you can do it this way:

```
bash$ BUILD=Debug ./build.sh
```

If you are working on changes and want to avoid rebuilding the `third-party`
dependencies on each build, you can accomplish this way:

```
bash$ TPBUILD=no ./build.sh
```

Our build is not very large and only takes a few seconds on our systems, but if
for some reason you feel it needs to be faster you can increase the `make`
parallelism by editing `build.sh`. Change the line from `make -j 1` and
increase the number to however many cores you have.

