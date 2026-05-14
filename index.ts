import net from "net";
import http from "http";
import events from "events";

import { Socks5Server } from "@pondwader/socks5-server";
import { HttpHandler, httpHandler } from "./http.js";

interface Options {
    ipAuthorization?: false | ((ip: string | null) => boolean | Promise<boolean>);
};

export interface AuthOptions<T = any> {
    ip?: string;
    username?: string;
    password?: string;

    destPort?: number;
    destAddress?: string;

    data?: T;
};

export interface ConnectionOptions<T = any> extends AuthOptions<T> {
    method: string;
    socket: net.Socket;
    protocol: "SOCKS5" | "HTTP";
};

export type Status = "GRANTED" | "FAILURE" | "NOT_ALLOWED" | "UNREACHABLE" | "NOT_SUPPORTED";

type AuthMiddleware<T = any> = (options: AuthOptions<T>, next: (data?: any) => Promise<boolean> | boolean) => Promise<boolean> | boolean;
type ConnectionMiddleware<T = any> = (options: ConnectionOptions<T>, submit: (status: Status) => void, next: (data?: any) => Promise<void> | void) => Promise<void> | void;


function normalize(ip?: string): string | null {
    if (!ip || typeof ip !== "string")
        return null;

    return ip;
};


export class ProxyServer extends events.EventEmitter {
    private authHandlers: Array<AuthMiddleware> = [];
    private connectionHandlers: Array<ConnectionMiddleware> = [];

    authHandler<T = any>(handler: AuthMiddleware<T>): this {
        if (typeof handler == "function")
            this.authHandlers.push(handler);

        return this;
    };

    connectionHandler<T = any>(handler: ConnectionMiddleware<T>): this {
        if (typeof handler == "function")
            this.connectionHandlers.push(handler);

        return this;
    };

    private async runAuthHandlers(options: AuthOptions): Promise<boolean> {
        let index = 0, next = async (data?: any): Promise<boolean> => {
            if (data !== undefined)
                options.data = data;

            if (index >= this.authHandlers.length)
                return true;

            return await (this.authHandlers[index++] as AuthMiddleware)(options, next) === true;
        };

        return await next();
    };

    private async runConnectionHandlers(options: ConnectionOptions, submit: (status: Status) => void): Promise<void> {
        let index = 0, next = async (data?: any): Promise<void> => {
            options.data = data;

            if (index >= this.connectionHandlers.length)
                return;

            await (this.connectionHandlers[index++] as ConnectionMiddleware)(options, submit, next);
        };

        await next();
    };


    private server?: net.Server;
    private httpServer = http.createServer();
    private socksServer = new Socks5Server();

    constructor(options?: Options) {
        super();
        const _ = this;
        const opts: Options = {
            ipAuthorization: false,
            ...(typeof options == "object" ? options : {})
        };

        this.server = new net.Server(async socket => {
            const ip = normalize(socket.remoteAddress);

            socket.once("data", async (buf: Buffer) => {
                const chunk = buf.at(0);

                if (!chunk || (chunk !== 0x05 && (chunk < 0x41 || chunk > 0x5a)))
                    return socket.destroy();

                if (opts.ipAuthorization && typeof opts.ipAuthorization == "function")
                    try {
                        if (!(await opts.ipAuthorization(ip)))
                            if (chunk === 0x05)
                                socket.write(Buffer.from([0x05, 0xFF]));
                            else
                                socket.write([
                                    "HTTP/1.1 403 Forbidden",

                                    "Connection: close",
                                    "Content-Type: text/plain",
                                    "Content-Length: 13",
                                    "",
                                    "Access Denied"
                                ].join("\r\n").concat("\r\n"));

                        return setTimeout(() => socket.destroy(), 10);
                    } catch (err) {
                        socket.destroy();
                        return _.emit("error", err);
                    };

                socket.unshift(buf);

                if (buf[0] == 0x05) {
                    _.socksServer._handleConnection(socket);
                } else
                    _.httpServer.emit("connection", socket);
            });

            socket.on("error", err => _.emit("error", err));
        });

        /// @ts-ignore
        const handleRequest: HttpHandler = async (req, socket) => {
            /// @ts-ignore
            const ip = normalize(socket.remoteAddress), options: AuthOptions = {
                ip: ip as string,
                username: req.username,
                password: req.password
            };

            if (req.method === "CONNECT") {
                const [host, port] = (req.url || "").split(":");

                options.destAddress = host as string;
                options.destPort = parseInt(port as string) || 443;
            } else
                try {
                    const url = new URL(req.url!.startsWith("http") ? req.url! : `http://${req.headers.host}${req.url}`);

                    options.destPort = parseInt(url.port) || 80;
                    options.destAddress = url.hostname;
                } catch {
                    options.destPort = 80;
                    options.destAddress = (req.headers.host || "").split(":")[0] as string;
                };

            if (_.authHandlers.length > 0) {
                if (!req.username || !req.password)
                    return socket.writeResponse(null, 407, {
                        "Proxy-Authenticate": 'Basic realm="Proxy Authentication Required"'
                    });

                const result = await _.runAuthHandlers(options);

                /// @ts-ignore
                socket.__result = options.data;

                if (!result)
                    return socket.writeResponse(null, 403);
            };

            let connectionOptions: ConnectionOptions = {
                ...options,
                data: (socket as any).__result,

                method: req.method!,
                socket: socket as net.Socket,
                protocol: "HTTP"
            };

            /// @ts-ignore
            delete socket.__result;

            if (_.connectionHandlers.length > 0)
                await _.runConnectionHandlers(connectionOptions, status => {
                    const map: Record<string, number> = {
                        "GRANTED": 200,
                        "FAILURE": 502,
                        "NOT_ALLOWED": 403,
                        "UNREACHABLE": 504,
                        "NOT_SUPPORTED": 501
                    };

                    if (status === "GRANTED") {
                        if (req.method === "CONNECT") socket.writeHead(200);
                    } else
                        socket.writeResponse(null, map[status] || 502);
                });
            else {
                const onHandshakeError = (err: any) => {
                    const map: Record<string, number> = {
                        "ETIMEDOUT": 504,
                        "ENOTFOUND": 504,
                        "ENETUNREACH": 504,
                        "ECONNREFUSED": 502
                    };

                    socket.writeResponse(null, map[err.code] || 502);
                };

                const target = net.createConnection({ host: options.destAddress, port: options.destPort }, () => {
                    if (req.method === "CONNECT")
                        socket.writeHead(200);

                    target.removeListener("error", onHandshakeError);

                    if (req.head)
                        target.write(req.head);


                    socket.on("error", (err: any) => {
                        if (err.code !== "ECONNRESET") _.emit("error", err);

                        target.destroy();
                    });

                    target.on("error", (err: any) => {
                        if (err.code !== "ECONNRESET") _.emit("error", err);

                        socket.destroy();
                    });

                    socket.pipe(target).pipe(socket);
                });

                target.setNoDelay(true);
                target.once("error", onHandshakeError);

                socket.on("close", () => target.destroy());
            };
        };

        this.httpServer
            .addListener("error", err => _.emit("error", err))
            .addListener("request", async (req) => httpHandler(req, req.socket, null, handleRequest))
            .addListener("connect", async (req, socket, head) => httpHandler(req, socket as net.Socket, head, handleRequest))
            .addListener("upgrade", async (req, socket, head) => httpHandler(req, socket as net.Socket, head, handleRequest));

        this.socksServer
            .setAuthHandler(async ({ socket, username, password, destAddress, destPort }, accept, deny) => {
                /// @ts-ignore
                const ip = normalize(socket.remoteAddress);

                try {
                    let options: AuthOptions = {
                        ip: ip as string,
                        username, password,
                        destPort: destPort as number,
                        destAddress: destAddress as string,
                    };

                    const result = await _.runAuthHandlers(options);

                    /// @ts-ignore
                    socket.__result = options.data;

                    result ? accept() : deny();
                } catch (err) {
                    _.emit("error", err);
                    return deny();
                };
            })
            .setConnectionHandler(async ({ socket, command, username, password, destAddress, destPort }, sendStatus) => {
                /// @ts-ignore
                const ip = normalize(socket.remoteAddress);

                if (command != "connect")
                    return sendStatus("COMMAND_NOT_SUPPORTED");

                try {
                    /// @ts-ignore
                    let options: ConnectionOptions = {
                        ip: ip as string,
                        username, password,
                        destPort: destPort as number,
                        destAddress: destAddress as string,

                        data: (socket as any).__result,

                        method: command,
                        socket: socket as net.Socket,
                        protocol: "SOCKS5"
                    };

                    /// @ts-ignore
                    delete socket.__result;

                    if (_.connectionHandlers.length > 0)
                        await _.runConnectionHandlers(options, status => {
                            const map: Record<string, any> = {
                                "GRANTED": "REQUEST_GRANTED",
                                "FAILURE": "GENERAL_FAILURE",
                                "UNREACHABLE": "HOST_UNREACHABLE",
                                "NOT_ALLOWED": "CONNECTION_NOT_ALLOWED",
                                "NOT_SUPPORTED": "ADDRESS_TYPE_NOT_SUPPORTED"
                            };

                            if (map[status]) sendStatus(map[status]);
                        });
                    else {
                        const onHandshakeError = (err: any) => {
                            const map: Record<string, string> = {
                                "ETIMEDOUT": "HOST_UNREACHABLE",
                                "ENOTFOUND": "HOST_UNREACHABLE",
                                "ENETUNREACH": "NETWORK_UNREACHABLE",
                                "ECONNREFUSED": "CONNECTION_REFUSED"
                            };

                            /// @ts-ignore
                            sendStatus(map[err.code] || "GENERAL_FAILURE");
                            socket.destroy();
                        };

                        const target = net.createConnection({ host: destAddress, port: destPort }, () => {
                            sendStatus("REQUEST_GRANTED");
                            target.removeListener("error", onHandshakeError);

                            socket.on("error", (err: any) => {
                                if (err.code !== "ECONNRESET") _.emit("error", err);

                                target.destroy();
                            });

                            target.on("error", (err: any) => {
                                if (err.code !== "ECONNRESET") _.emit("error", err);

                                socket.destroy();
                            });

                            socket.pipe(target).pipe(socket);
                        });

                        target.setNoDelay(true);
                        target.once("error", onHandshakeError);

                        socket.on("close", () => target.destroy());
                    };
                } catch (err) { _.emit("error", err); };
            });
    };

    listen(port?: number, listener?: () => void): this;
    listen(port?: number, hostname?: string, listener?: () => void): this;
    listen(port?: number, hostnameOrListener?: string | (() => void), listener?: () => void): this {
        if (!this.server)
            return this;

        if (this.authHandlers.length === 0)
            this.socksServer.disableAuthHandler();

        if (typeof hostnameOrListener === "function")
            this.server.listen(port, hostnameOrListener);
        else
            this.server.listen(port, hostnameOrListener, listener);

        return this;
    };
};