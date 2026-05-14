import { Socket } from "net";
import { IncomingMessage, STATUS_CODES } from "http";

export type HttpHandler = (req: IncomingMessage & { username?: string, password?: string, head: NonSharedBuffer | null }, socket: Socket & { writeHead: (statusCode: number, headers?: Record<string, string>) => void, writeResponse: (data: string | null, statusCode: number, headers?: Record<string, string>) => void }) => Promise<void>;

export async function httpHandler(req: IncomingMessage, socket: Socket, head: NonSharedBuffer | null, callback: HttpHandler) {
    const authorization = req.headers["proxy-authorization"]; if (authorization && authorization.startsWith("Basic "))
        try {
            let [, base64] = authorization.split(" ");

            if (base64) {
                let [username, password] = Buffer.from(base64, "base64").toString().split(":");

                if (typeof username == "string" && username.length > 0)
                    Object.assign(req, { username });

                if (typeof password == "string" && password.length > 0)
                    Object.assign(req, { password });
            };
        } catch { };

    const writeHead = (statusCode: number, headers: Record<string, string> = {}, data?: string | null) => {
        let response = `HTTP/1.1 ${statusCode}`;
        if (STATUS_CODES[statusCode]) response += ` ${STATUS_CODES[statusCode]}`;

        response += "\r\n";

        for (const [key, value] of Object.entries(headers))
            response += `${key.toLocaleLowerCase()}: ${value}\r\n`;

        response += "\r\n";

        if (typeof data == "string" && data.length > 0)
            response += data + "\r\n";

        socket.write(response);
    };

    await callback(Object.assign(req, { head }), Object.assign(socket, {
        writeHead, writeResponse: (data: string | null, statusCode: number, headers: Record<string, string> = {}) => {
            headers["Connection"] = "close";

            if (typeof data == "string" && data.length > 0) {
                headers["Content-Type"] = "text/plain";
                headers["Content-Length"] = data.length.toString();
            };

            writeHead(statusCode, headers, data);
            return setTimeout(() => socket.destroy(), 10);
        }
    }));
};