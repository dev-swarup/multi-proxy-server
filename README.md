## Multiplex Proxy
A Commercial-Grade, High-Performance Node.js proxy solution that multiplexes <b>HTTP</b> and <b>SOCKS5</b> protocols onto a single TCP port.

## Features
- Protocol Multiplexing: Automatically detects and routes <b>SOCKS5</b> and <b>HTTP/HTTPS</b> traffic on the same port.
- Middleware Architecture: Sequential `authHandler` and `connectionHandler` chains for complex logic.

## Installation
```bash
npm install multiplex-proxy
```

## Quick Start
```typescript
import { ProxyServer } from "multiplex-proxy";

const Server = new ProxyServer();

Server.listen(8080, () => {
    console.log("Multiplex Proxy running on port 8080");
});
```

## Documentation
### Authentication Middleware (`authHandler`)
```typescript
Server.authHandler(async (options, next) => {
    const { ip, username, password } = options;

    if (ip === "127.0.0.1") {
        // Pass data to the next handler or metrics
        return next({ plan: "premium", userId: "admin" });
    }

    return username === "user" && password === "pass" ? next() : false;
});
```

### Connection Middleware (`connectionHandler`)
```typescript
Server.connectionHandler(async (options, submit, next) => {
    const { protocol, destAddress, destPort } = options;

    const upstream = net.createConnection({ host: "upstream.com", port: 9000 }, () => {
        submit("GRANTED");
        options.socket.pipe(upstream).pipe(options.socket);
    });

    await next();
});
```