# SDB - Slim GDB
## A light weight gdb-like debugger for linux x86_64!

## Requirements
Note that only **debian based** distributions are supported.

First, clone this repo to your local machine. Then, update the apt manager
```bash
sudo apt-get update
```

### cmake installation
The required build system for this repo is `cmake`, which means it has to be installed.

If you do not have `cmake`, run the following:
```bash
sudo apt install cmake
```
### dependencies
Great! now let's install the code dependencies by running
```bash
sudo apt install libelf-dev libzydis-dev zydis-tools libreadline-dev
```
That's it!

## compile and run
From the root of this repo, run
```bash
cmake src
cmake --build .
```
A new binary `./sdb` will be created, you're good to go!

## Build With Docker
Whether you like docker or your machine is incompatible with the requirements, a `Dockerfile` is available for build.
```bash
docker build -t sdb .
docker run -it --rm sdb
```
You will find yourself in a directory with the source code and `./sdb` compiled.

On top of that, the `sdb` binary exists in `PATH`.
