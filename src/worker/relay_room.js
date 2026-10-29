import { Buffer } from 'buffer';
import { parseHeader, createHeader } from './core/packet.js';
import { PacketType, HEADER_SIZE, MY_PEER_ID } from './core/constants.js';
import { loadProtos } from './core/protos.js';
import { handleHandshake, handlePing, handleForwarding } from './core/basic_handlers.js';
import { handleRpcReq, handleRpcResp } from './core/rpc_handler.js';
import { PeerManager } from './core/peer_manager.js';
import { randomU64String, wrapPacket } from './core/crypto.js';

const WS_OPEN = 1;
const CONN_VERSION_KEY = 'connVersion';
// Attachments survive hibernation; refreshing lastSeen there on every packet is wasteful.
const LAST_SEEN_PERSIST_MS = 5000;

export class RelayRoom {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.types = loadProtos();
    // One PeerManager per room. All in-memory state is lost on hibernation or eviction and
    // rebuilt from the sockets' attachments plus the persisted conn version below.
    this.peerManager = new PeerManager({
      onConnVersionChange: (v) => {
        this.state.storage.put(CONN_VERSION_KEY, v).catch((e) => console.error('persist conn version failed:', e));
      },
    });
    this.peerManager.setTypes(this.types);

    // Silent peers get a Ping after pingIntervalMs and are dropped after connTimeoutMs.
    // Clients answer every Ping with a Pong, and any packet counts as a sign of life.
    this.pingIntervalMs = Number(env.EASYTIER_PING_INTERVAL_MS || 10_000);
    this.connTimeoutMs = Number(env.EASYTIER_CONN_TIMEOUT_MS || 35_000);

    this.state.blockConcurrencyWhile(async () => {
      // Must be restored before any socket can bump it, or the version could go backwards.
      this.peerManager.restoreConnVersion(await this.state.storage.get(CONN_VERSION_KEY));
      const sockets = this.state.getWebSockets();
      sockets.forEach((ws) => this._restoreSocket(ws));
      if (sockets.length > 0) await this._ensureAlarm();
    });
  }

  async fetch(request) {
    const url = new URL(request.url);
    const wsPath = '/' + this.env.WS_PATH || '/ws';
    if (url.pathname !== wsPath) {
      return new Response('Not found', { status: 404 });
    }
    if (request.headers.get('Upgrade') !== 'websocket') {
      return new Response('Expected websocket', { status: 400 });
    }

    const pair = new WebSocketPair();
    const server = pair[1];
    const client = pair[0];
    await this.handleSession(server);

    return new Response(null, { status: 101, webSocket: client });
  }

  async handleSession(webSocket) {
    this.state.acceptWebSocket(webSocket);
    this._initSocket(webSocket);
    this._saveAttachment(webSocket);
    await this._ensureAlarm();
  }

  async webSocketMessage(ws, message) {
    try {
      let buffer = null;
      if (message instanceof ArrayBuffer) {
        buffer = Buffer.from(message);
      } else if (message instanceof Uint8Array) {
        buffer = Buffer.from(message);
      } else if (ArrayBuffer.isView(message) && message.buffer) {
        buffer = Buffer.from(message.buffer);
      } else {
        console.warn('[ws] unsupported message type', typeof message);
        return;
      }
      console.log(`[ws] recv len=${buffer.length}`);
      this._touch(ws);
      const header = parseHeader(buffer);
      if (!header) {
        console.error('[ws] parseHeader failed, raw hex=', buffer.toString('hex'));
        return;
      }
      console.log(`[ws] header from=${header.fromPeerId} to=${header.toPeerId} type=${header.packetType} len=${header.len}`);
      const payload = buffer.subarray(HEADER_SIZE);
      switch (header.packetType) {
        case PacketType.HandShake:
          console.log(`[ws] -> handleHandshake payload hex=${payload.toString('hex')}`);
          handleHandshake(ws, header, payload, this.types);
          break;
        case PacketType.Ping:
          handlePing(ws, header, payload);
          break;
        case PacketType.Pong:
          // Echo of our own liveness Ping: receiving it already refreshed lastSeen.
          if (header.fromPeerId === MY_PEER_ID) break;
          handleForwarding(ws, header, buffer, this.types);
          break;
        case PacketType.RpcReq:
          if (header.toPeerId === undefined || header.toPeerId === null) {
            handleRpcReq(ws, header, payload, this.types);
            break;
          }
          if (header.toPeerId === MY_PEER_ID) {
            handleRpcReq(ws, header, payload, this.types);
            break;
          }
          handleForwarding(ws, header, buffer, this.types);
          break;
        case PacketType.RpcResp:
          if (header.toPeerId === undefined || header.toPeerId === null || header.toPeerId === MY_PEER_ID) {
            handleRpcResp(ws, header, payload, this.types);
            break;
          }
          // If toPeerId is not MY_PEER_ID, forward to the target peer
          console.log(`[ws] -> forward RpcResp type=${header.packetType} from=${header.fromPeerId} to=${header.toPeerId} len=${payload.length}`);
          handleForwarding(ws, header, buffer, this.types);
          break;
        case PacketType.Data:
        default:
          if (header.packetType !== PacketType.Data) {
            console.log(`[ws] -> forward type=${header.packetType} len=${payload.length}`);
          }
          handleForwarding(ws, header, buffer, this.types);
      }
    } catch (e) {
      console.error('relay_room message handling error:', e);
      try { ws.close(1011, 'internal error'); } catch (_) { }
      this._dropPeer(ws);
    }
  }

  async webSocketClose(ws) {
    this._dropPeer(ws);
    // Complete the closing handshake.
    try { ws.close(1000, 'closed'); } catch (_) { }
  }

  async webSocketError(ws) {
    this._dropPeer(ws);
  }

  // Liveness check. A peer that vanished without a close frame (network loss, sleep,
  // killed process) would otherwise stay registered until the runtime notices, which can
  // take a very long time, and keep being advertised to everyone else.
  async alarm() {
    const now = Date.now();
    for (const ws of this.state.getWebSockets()) {
      const silentFor = now - (ws.lastSeen || now);
      if (silentFor > this.connTimeoutMs) {
        console.log(`[liveness] peer ${ws.peerId} silent for ${silentFor}ms, dropping`);
        try { ws.close(1001, 'liveness timeout'); } catch (_) { }
        this._dropPeer(ws);
        continue;
      }
      if (ws.peerId && silentFor >= this.pingIntervalMs) {
        this._sendPing(ws);
      }
    }
    await this._ensureAlarm(true);
  }

  async _ensureAlarm(reschedule = false) {
    if (this.state.getWebSockets().length === 0) return;
    if (!reschedule && (await this.state.storage.getAlarm()) !== null) return;
    await this.state.storage.setAlarm(Date.now() + this.pingIntervalMs);
  }

  _sendPing(ws) {
    if (ws.readyState !== WS_OPEN) return;
    try {
      ws.send(wrapPacket(createHeader, MY_PEER_ID, ws.peerId, PacketType.Ping, Buffer.alloc(4), ws));
    } catch (e) {
      console.error(`[liveness] ping to ${ws.peerId} failed:`, e);
    }
  }

  _dropPeer(ws) {
    if (!ws.peerId) return;
    const groupKey = ws.groupKey;
    // False when this socket was already replaced by a newer one of the same peer.
    if (this.peerManager.removePeer(ws)) {
      try {
        this.peerManager.broadcastRouteUpdate(this.types, groupKey);
      } catch (e) {
        console.error('broadcast after peer removal failed:', e);
      }
    }
  }

  _touch(ws) {
    const now = Date.now();
    ws.lastSeen = now;
    if (now - (ws.lastSeenSaved || 0) > LAST_SEEN_PERSIST_MS) {
      this._saveAttachment(ws);
    }
  }

  _saveAttachment(ws) {
    ws.lastSeenSaved = ws.lastSeen;
    ws.serializeAttachment?.({
      peerId: ws.peerId,
      groupKey: ws.groupKey,
      domainName: ws.domainName,
      serverSessionId: ws.serverSessionId,
      lastSeen: ws.lastSeen,
    });
  }

  _initSocket(ws, meta = {}) {
    ws.peerManager = this.peerManager;
    ws.peerId = meta.peerId || null;
    ws.groupKey = meta.groupKey || null;
    ws.domainName = meta.domainName || null;
    ws.lastSeen = meta.lastSeen || Date.now();
    ws.serverSessionId = meta.serverSessionId || randomU64String();
    ws.weAreInitiator = false;
    ws.crypto = { enabled: false };
  }

  _restoreSocket(ws) {
    const meta = ws.deserializeAttachment ? (ws.deserializeAttachment() || {}) : {};
    this._initSocket(ws, meta);
    if (ws.peerId && ws.groupKey) {
      // Peer infos and route sessions did not survive. A fresh session id makes the
      // client discard what it thinks we know and resend its own peer info.
      ws.serverSessionId = randomU64String();
      this.peerManager.addPeer(ws.peerId, ws, { restoring: true });
    }
    this._saveAttachment(ws);
  }
}
