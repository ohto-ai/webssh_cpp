# webssh_cpp

A WebSSH server written in C++17. It serves a browser terminal with [xterm.js](https://xtermjs.org/) and bridges WebSocket traffic to SSH sessions via [libssh2](https://www.libssh2.org/), using [libhv](https://github.com/ithewei/libhv) for HTTP / WebSocket serving.

## Features

- Browser-based SSH terminal (xterm.js frontend)
- WebSocket streaming between the browser and the SSH PTY
- Password authentication via libssh2
- Multiple SSH sessions / channels, with read-only WebSocket attach support
- Terminal size and `TERM` environment propagation
- Configurable listen address and port
- Structured logging with spdlog
- Catch2 unit tests for the SSH connection layer

## Requirements

- CMake 3.10+
- C++17 compiler
- OpenSSL
- Git (for submodules)

The following dependencies are vendored as git submodules under `3rd/`:

- [libhv](https://github.com/ithewei/libhv)
- [libssh2](https://github.com/libssh2/libssh2)
- [spdlog](https://github.com/gabime/spdlog)
- [Catch2](https://github.com/catchorg/Catch2)

## Build

```bash
git submodule update --init --recursive

cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --target webssh_cpp -j8
```

On Windows with Visual Studio, specify the architecture:

```powershell
cmake -B build -A x64
cmake --build build --config Release --target webssh_cpp -j8
```

## Run

```bash
./build/src/webssh_cpp
```

Then open <http://localhost:8080/> and enter the target host, port, username, and password.

Command-line options:

```text
Usage: webssh_cpp [-d] [-p port] [-a address]
  -d          Enable debug logging
  -p port     Listen port (default: 8080)
  -a address  Listen address (default: 0.0.0.0)
  -h          Show this help
```

## Tests

The test suite uses Catch2 and is registered with CTest:

```bash
cmake --build build -j8
ctest --test-dir build --output-on-failure
```

## Project layout

```text
src/main.cpp              HTTP / WebSocket server and SSH session wiring
src/ssh_connection/       libssh2 session, channel, and PTY management
src/inc/mini_buffer.hpp   small buffer utility
static/                   xterm.js / Bootstrap frontend
test/                     Catch2 tests
3rd/                      vendored dependencies (git submodules)
```

## Security notes

- The server uses plain HTTP and password-based SSH authentication. Do not expose it directly to the public internet.
- Put it behind a TLS-terminating reverse proxy (e.g. Nginx / Caddy) and add network-level access control and authentication if needed.
- Credentials are sent from the browser to the webssh server; only run it on a trusted network or with HTTPS.

## License

[MIT](LICENSE)
