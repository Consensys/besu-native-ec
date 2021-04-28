# besu-native-ec

This C library is a wrapper for OpenSSL elliptic curve signature implementations.

## Prerequisites

### Linux

You'll need to be sure that gcc, make, autoconf, automake, and libtool are installed. If you are
building on Ubuntu or Debian, the following command will install these dependencies for you:

```
sudo apt-get install build-essential automake autoconf libtool
```

### OS X

You'll need to be sure that XCode Command Line Tools, make, autoconf, automake, and libtool are
installed. The easiest way to do this is to install [Homebrew](https://brew.sh/), and then run the
following command. Note that installing Homebrew will automatically install the XCode command line
tools.

```
brew install autoconf automake libtool
```

## Setup

After cloning the project you need to initialize the Git submodule which points to OpenSSL and compile it. This can be done by executing
```
./setup.sh
```
This needs to be done only once.

## Building
To build the library and execute the test execute
```
./build.sh
```