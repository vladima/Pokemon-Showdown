/**
 * Connections
 * Pokemon Showdown - http://pokemonshowdown.com/
 *
 * Abstraction layer for multi-process SockJS connections.
 *
 * This file handles all the communications between the users'
 * browsers, the networking processes, and users.js in the
 * main process.
 *
 * @license MIT license
 */

'use strict';

import * as cluster from 'cluster';
import { Config } from "./config/config";
import * as Users from "./users"
import * as http from "http"
import * as sockjs from 'sockjs';

export type Worker = cluster.Worker;

// master
export let workers: Dict<cluster.Worker>;
export let killWorker: (worker: cluster.Worker) => void;
export let killPid: (pid: PID) => void;
export let socketSend: (worker: cluster.Worker, socketid: SockedId, message: string) => void;
export let socketDisconnect: (worker: cluster.Worker, socketid: SockedId) => void;
export let channelBroadcast: (channelid: ChannelId, message: string) => void;
export let channelSend: (worker: cluster.Worker, channelid: ChannelId, message: string) => void;
export let channelAdd: (worker: cluster.Worker, channelid: ChannelId, socketid: SockedId) => void;
export let channelRemove: (worker: cluster.Worker, channelid: ChannelId, socketid: SockedId) => void;
export let subchannelBroadcast: (channelid: ChannelId, message: string) => void;
export let subchannelMove: (worker: cluster.Worker, channelid: ChannelId, subchannelid: ChannelId, socketid: SockedId) => void;
// worker

if (cluster.isMaster) {
    cluster.setupMaster({
        exec: require('path').resolve(__dirname, 'sockets.js')
    });

    workers = {};

    let spawnWorker = exports.spawnWorker = function() {
        let worker = cluster.fork({ PSPORT: Config.port, PSBINDADDR: Config.bindaddress || '', PSNOSSL: Config.ssl ? 0 : 1 });
        let id = worker.id;
        workers[id] = worker;
        worker.on('message', function(data) {
            // console.log('master received: ' + data);
            switch (data.charAt(0)) {
                case '*': {
                    // *socketid, ip
                    // connect
                    let nlPos = data.indexOf('\n');
                    Users.socketConnect(worker, id, data.substr(1, nlPos - 1), data.substr(nlPos + 1));
                    break;
                }

                case '!': {
                    // !socketid
                    // disconnect
                    Users.socketDisconnect(worker, id, data.substr(1));
                    break;
                }

                case '<': {
                    // <socketid, message
                    // message
                    let nlPos = data.indexOf('\n');
                    Users.socketReceive(worker, id, data.substr(1, nlPos - 1), data.substr(nlPos + 1));
                    break;
                }

                default:
                // unhandled
            }
        });
    };

    let workerCount = typeof Config.workers !== 'undefined' ? Config.workers : 1;
    for (let i = 0; i < workerCount; i++) {
        spawnWorker();
    }

    killWorker = function(worker) {
        let idd = worker.id + '-';
        let count = 0;
        Users.connections.forEach(function(connection, connectionid) {
            if (connectionid.substr(idd.length) === idd) {
                Users.socketDisconnect(worker, worker.id, connection.socketid);
                count++;
            }
        });
        try {
            worker.kill();
        } catch (e) { }
        delete workers[worker.id];
        return count;
    };

    killPid = function(pid) {
        pid = '' + pid;
        for (let id in workers) {
            let worker = workers[id];
            if (pid === '' + worker.process.pid) {
                return this.killWorker(worker);
            }
        }
        return false;
    };

    socketSend = function(worker, socketid, message) {
        worker.send('>' + socketid + '\n' + message);
    };
    socketDisconnect = function(worker, socketid) {
        worker.send('!' + socketid);
    };

    channelBroadcast = function(channelid, message) {
        for (let workerid in workers) {
            workers[workerid].send('#' + channelid + '\n' + message);
        }
    };
    channelSend = function(worker, channelid, message) {
        worker.send('#' + channelid + '\n' + message);
    };
    channelAdd = function(worker, channelid, socketid) {
        worker.send('+' + channelid + '\n' + socketid);
    };
    channelRemove = function(worker, channelid, socketid) {
        worker.send('-' + channelid + '\n' + socketid);
    };

    subchannelBroadcast = function(channelid, message) {
        for (let workerid in workers) {
            workers[workerid].send(':' + channelid + '\n' + message);
        }
    };
    subchannelMove = function(worker, channelid, subchannelid, socketid) {
        worker.send('.' + channelid + '\n' + subchannelid + '\n' + socketid);
    };
} else {
    // is worker

    if (process.env.PSPORT) Config.port = +process.env.PSPORT;
    if (process.env.PSBINDADDR) Config.bindaddress = process.env.PSBINDADDR;
    if (+process.env.PSNOSSL) Config.ssl = null;

    // ofe is optional
    // if installed, it will heap dump if the process runs out of memory
    try {
        require('ofe').call();
    } catch (e) { }

    // Static HTTP server

    // This handles the custom CSS and custom avatar features, and also
    // redirects yourserver:8001 to yourserver-8001.psim.us

    // It's optional if you don't need these features.

    global.Cidr = require('./cidr');

    if (Config.crashguard) {
        // graceful crash
        process.on('uncaughtException', function(err: Error) {
            require('./crashlogger.js')(err, 'Socket process ' + cluster.worker.id + ' (' + process.pid + ')', true);
        });
    }

    let app = http.createServer();
    let appssl: http.Server;
    if (Config.ssl) {
        appssl = http.createServer(Config.ssl.options);
    }
    try {
        (function() {
            let nodestatic = require('node-static');
            let cssserver = new nodestatic.Server('./config');
            let avatarserver = new nodestatic.Server('./config/avatars');
            let staticserver = new nodestatic.Server('./static');
            let staticRequestHandler = function(request, response) {
                // console.log("static rq: " + request.socket.remoteAddress + ":" + request.socket.remotePort + " -> " + request.socket.localAddress + ":" + request.socket.localPort + " - " + request.method + " " + request.url + " " + request.httpVersion + " - " + request.rawHeaders.join('|'));
                request.resume();
                request.addListener('end', function() {
                    if (Config.customhttpresponse &&
                        Config.customhttpresponse(request, response)) {
                        return;
                    }
                    let server;
                    if (request.url === '/custom.css') {
                        server = cssserver;
                    } else if (request.url.substr(0, 9) === '/avatars/') {
                        request.url = request.url.substr(8);
                        server = avatarserver;
                    } else {
                        if (/^\/([A-Za-z0-9][A-Za-z0-9-]*)\/?$/.test(request.url)) {
                            request.url = '/';
                        }
                        server = staticserver;
                    }
                    server.serve(request, response, function(e, res) {
                        if (e && (e.status === 404)) {
                            staticserver.serveFile('404.html', 404, {}, request, response);
                        }
                    });
                });
            };
            app.on('request', staticRequestHandler);
            if (appssl) {
                appssl.on('request', staticRequestHandler);
            }
        })();
    } catch (e) {
        console.log('Could not start node-static - try `npm install` if you want to use it');
    }

    // SockJS server

    // This is the main server that handles users connecting to our server
    // and doing things on our server.

	

    let server = sockjs.createServer({
        sockjs_url: "//play.pokemonshowdown.com/js/lib/sockjs-0.3.min.js",
        log: function(severity, message) {
            if (severity === 'error') console.log('ERROR: ' + message);
        },
        prefix: '/showdown',
        websocket: !Config.disablewebsocket
    });

    let sockets: Dict<sockjs.SockJSConnection> = {};
    let channels: Dict<Dict<void>> = {};
    let subchannels: Dict<Dict<void>> = {};
    // Deal with phantom connections.
    let sweepClosedSockets = function() {
        for (let s in sockets) {
            if (sockets[s].protocol === 'xhr-streaming' &&
                sockets[s]._session &&
                sockets[s]._session.recv) {
                sockets[s]._session.recv.didClose();
            }

            // A ghost connection's `_session.to_tref._idlePrev` (and `_idleNext`) property is `null` while
            // it is an object for normal users. Under normal circumstances, those properties should only be
            // `null` when the timeout has already been called, but somehow it's not happening for some connections.
            // Simply calling `_session.timeout_cb` (the function bound to the aformentioned timeout) manually
            // on those connections kills those connections. For a bit of background, this timeout is the timeout
            // that sockjs sets to wait for users to reconnect within that time to continue their session.
            if (sockets[s]._session &&
                sockets[s]._session.to_tref &&
                !sockets[s]._session.to_tref._idlePrev) {
                sockets[s]._session.timeout_cb();
            }
        }
    };
    let interval = setInterval(sweepClosedSockets, 1000 * 60 * 10); // eslint-disable-line no-unused-vars

    process.on('message', function(data: string) {
        // console.log('worker received: ' + data);
        let socket: sockjs.SockJSConnection = null, socketid = '';
        let channel = null, channelid: ChannelId = '';
        let subchannel = null, subchannelid: ChannelId = '';

        switch (data.charAt(0)) {
            case '$': // $code
                eval(data.substr(1));
                break;

            case '!': // !socketid
                // destroy
                socketid = data.substr(1);
                socket = sockets[socketid];
                if (!socket) return;
                socket.end();
                // After sending the FIN packet, we make sure the I/O is totally blocked for this socket
                socket.destroy();
                delete sockets[socketid];
                for (channelid in channels) {
                    delete channels[channelid][socketid];
                }
                break;

            case '>': {
                // >socketid, message
                // message
                let nlLoc = data.indexOf('\n');
                socket = sockets[data.substr(1, nlLoc - 1)];
                if (!socket) return;
                socket.write(data.substr(nlLoc + 1));
                break;
            }

            case '#': {
                // #channelid, message
                // message to channel
                let nlLoc = data.indexOf('\n');
                channel = channels[data.substr(1, nlLoc - 1)];
                let message = data.substr(nlLoc + 1);
                for (socketid in channel) {
                    channel[socketid].write(message);
                }
                break;
            }

            case '+': {
                // +channelid, socketid
                // add to channel
                let nlLoc = data.indexOf('\n');
                socketid = data.substr(nlLoc + 1);
                socket = sockets[socketid];
                if (!socket) return;
                channelid = data.substr(1, nlLoc - 1);
                channel = channels[channelid];
                if (!channel) channel = channels[channelid] = Object.create(null);
                channel[socketid] = socket;
                break;
            }

            case '-': {
                // -channelid, socketid
                // remove from channel
                let nlLoc = data.indexOf('\n');
                channelid = data.slice(1, nlLoc);
                channel = channels[channelid];
                if (!channel) return;
                socketid = data.slice(nlLoc + 1);
                delete channel[socketid];
                if (subchannels[channelid]) delete subchannels[channelid][socketid];
                let isEmpty = true;
                for (let socketid in channel) { // eslint-disable-line no-unused-vars
                    isEmpty = false;
                    break;
                }
                if (isEmpty) {
                    delete channels[channelid];
                    delete subchannels[channelid];
                }
                break;
            }

            case '.': {
                // .channelid, subchannelid, socketid
                // move subchannel
                let nlLoc = data.indexOf('\n');
                channelid = data.slice(1, nlLoc);
                let nlLoc2 = data.indexOf('\n', nlLoc + 1);
                subchannelid = data.slice(nlLoc + 1, nlLoc2);
                socketid = data.slice(nlLoc2 + 1);

                subchannel = subchannels[channelid];
                if (!subchannel) subchannel = subchannels[channelid] = Object.create(null);
                if (subchannelid === '0') {
                    delete subchannel[socketid];
                } else {
                    subchannel[socketid] = subchannelid;
                }
                break;
            }

            case ':': {
                // :channelid, message
                // message to subchannel
                let nlLoc = data.indexOf('\n');
                channelid = data.slice(1, nlLoc);
                channel = channels[channelid];
                subchannel = subchannels[channelid];
                let message = data.substr(nlLoc + 1);
                let messages: string[] = [null, null, null];
                for (socketid in channel) {
                    switch (subchannel ? subchannel[socketid] : '0') {
                        case '1':
                            if (!messages[1]) {
                                messages[1] = message.replace(/\n\|split\n[^\n]*\n([^\n]*)\n[^\n]*\n[^\n]*/g, '\n$1');
                            }
                            channel[socketid].write(messages[1]);
                            break;
                        case '2':
                            if (!messages[2]) {
                                messages[2] = message.replace(/\n\|split\n[^\n]*\n[^\n]*\n([^\n]*)\n[^\n]*/g, '\n$1');
                            }
                            channel[socketid].write(messages[2]);
                            break;
                        default:
                            if (!messages[0]) {
                                messages[0] = message.replace(/\n\|split\n([^\n]*)\n[^\n]*\n[^\n]*\n[^\n]*/g, '\n$1');
                            }
                            channel[socketid].write(messages[0]);
                            break;
                    }
                }
                break;
            }

            default:
        }
    });

    process.on('disconnect', function() {
        process.exit();
    });

    // this is global so it can be hotpatched if necessary
    let isTrustedProxyIp = Cidr.checker(Config.proxyip);
    let socketCounter = 0;
    server.on('connection', function(socket: sockjs.SockJSConnection) {
        if (!socket) {
            // For reasons that are not entirely clear, SockJS sometimes triggers
            // this event with a null `socket` argument.
            return;
        } else if (!socket.remoteAddress) {
            // This condition occurs several times per day. It may be a SockJS bug.
            try {
                socket.end();
            } catch (e) { }
            return;
        }
        let socketid = socket.id = (++socketCounter);

        sockets[socket.id] = socket;

        if (isTrustedProxyIp(socket.remoteAddress)) {
            let ips = (socket.headers['x-forwarded-for'] || '').split(',');
            let ip: string;
            while ((ip = ips.pop())) {
                ip = ip.trim();
                if (!isTrustedProxyIp(ip)) {
                    socket.remoteAddress = ip;
                    break;
                }
            }
        }

        process.send('*' + socketid + '\n' + socket.remoteAddress);

        socket.on('data', function(message: string | {}) {
            // drop empty messages (DDoS?)
            if (!message) return;
            // drop legacy JSON messages
            if (typeof message !== 'string' || message.charAt(0) === '{') return;
            // drop blank messages (DDoS?)
            let pipeIndex = (<string>message).indexOf('|');
            if (pipeIndex < 0 || pipeIndex === (<string>message).length - 1) return;

            process.send('<' + socketid + '\n' + message);
        });

        socket.on('close', function() {
            process.send('!' + socketid);
            delete sockets[socketid];
            for (let channelid in channels) {
                delete channels[channelid][socketid];
            }
        });
    });
    server.installHandlers(app, {});
    if (!Config.bindaddress) Config.bindaddress = '0.0.0.0';
    app.listen(Config.port, Config.bindaddress);
    console.log('Worker ' + cluster.worker.id + ' now listening on ' + Config.bindaddress + ':' + Config.port);

    if (appssl) {
        server.installHandlers(appssl, {});
        appssl.listen(Config.ssl.port, Config.bindaddress);
        console.log('Worker ' + cluster.worker.id + ' now listening for SSL on port ' + Config.ssl.port);
    }

    console.log('Test your server at http://' + (Config.bindaddress === '0.0.0.0' ? 'localhost' : Config.bindaddress) + ':' + Config.port);

    require('./repl.js').start('sockets-', cluster.worker.id + '-' + process.pid, function(cmd: string) { return eval(cmd); });
}
