interface Dict<T> {
    [i: string]: T;
}

declare type RoomId = void;
declare type RoomTitle = string | RoomId;

declare type LockedRange = NodeJS.Timer;
declare type UserId = string;
declare type ConnectionId = void;
declare type IpAddress = string;
declare type SSL = {
    options: void;
    port: number;
};

declare type PID = string;
declare type SockedId = void;
declare type ChannelId = string;
declare type Group = string;
declare type ChallengeTo = void;

declare module "sockjs" {
    import * as http from "http";
    import * as events from "events";
    interface Options {
        sockjs_url: string;
        log(severity: string, message: string): void;
        prefix: string;
        websocket: boolean
    }
    interface SockJSServer extends http.Server {
        installHandlers(server: http.Server, handlerOptions: Dict<string>): void;
    }
    interface SockJSConnection extends NodeJS.EventEmitter {
        readable: boolean;
        writable: boolean;
        remoteAddress: string;
        remotePort: number;
        address: string;
        headers: Dict<string>;
        url: string;
        end(): void;
        destroy(): void;
        write(message: string): void;
        protocol: string;
        _session: SockJSSession;
        id: number;
    }

    interface SockJSSession {
        recv: SockJSRecv 
        to_tref: NodeJS.Timer;
        timeout_cb: Function;
    }
    
    interface SockJSRecv {
        didClose(): void;
    }

    interface SockJSToRef {
        didClose(): void;
    }
    
    function createServer(options: Options): SockJSServer;
}