import { Buffer } from 'buffer';
import { MY_PEER_ID, PacketType } from './constants.js';
import { createHeader } from './packet.js';
import { wrapPacket, randomU64String } from './crypto.js';

const WS_OPEN = 1; // WebSocket.OPEN in CF runtime

function parseIpv4ToU32Be(ip) {
  const parts = String(ip).trim().split('.').map(x => Number(x));
  if (parts.length !== 4 || parts.some(x => !Number.isInteger(x) || x < 0 || x > 255)) {
    throw new Error(`Invalid IPv4: ${ip}`);
  }
  return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}

function mask32FromLen(len) {
  const l = Number(len);
  if (!Number.isFinite(l) || l <= 0) return 0;
  if (l >= 32) return 0xFFFFFFFF >>> 0;
  return (0xFFFFFFFF << (32 - l)) >>> 0;
}

function deriveSameNetworkIpv4(peerAddr, networkLength, myPeerId) {
  const mask = mask32FromLen(networkLength);
  const net = (peerAddr >>> 0) & mask;
  const hostBits = 32 - Number(networkLength);
  if (!Number.isFinite(hostBits) || hostBits <= 1 || hostBits > 30) {
    return null;
  }
  const hostMax = (1 << hostBits) >>> 0;
  const peerHost = (peerAddr >>> 0) & (~mask >>> 0);
  let host = (Number(myPeerId) % 250) + 2;
  if (host >= hostMax) {
    host = (Number(myPeerId) % Math.max(hostMax - 2, 1)) + 1;
  }
  if (host === peerHost) {
    host = (host + 1) % hostMax;
    if (host === 0) host = 1;
  }
  return (net | host) >>> 0;
}

function makeInstId() {
  return {
    part1: Number(BigInt.asUintN(32, BigInt(randomU64String()))),
    part2: Number(BigInt.asUintN(32, BigInt(randomU64String()))),
    part3: Number(BigInt.asUintN(32, BigInt(randomU64String()))),
    part4: Number(BigInt.asUintN(32, BigInt(randomU64String()))),
  };
}

export class PeerManager {
  constructor(opts = {}) {
    this.peersByGroup = new Map(); // groupKey -> Map(peerId -> ws), only peers with a live socket
    this.peerInfosByGroup = new Map(); // groupKey -> Map(peerId -> peerInfo), only the live peers' own infos
    this.routeSessions = new Map(); // groupKey -> peerId -> session state
    this.networkDigestRegistry = new Map(); // networkName -> first registered secret digest
    this.peerCenterStateByGroup = new Map(); // groupKey -> PeerCenterRpc state
    this.lastPeerCenterClean = 0;
    this.types = null;

    // Version of the server's own row in the conn bitmap. Clients only accept a row whose
    // version is strictly larger than the one they hold, so this must never go backwards,
    // not even across Durable Object restarts: it is persisted through onConnVersionChange.
    this.connVersion = 0;
    this.onConnVersionChange = opts.onConnVersionChange || null;

    this.allowVirtualIP = false;
    this.ipConfiguredByEnv = !!process.env.EASYTIER_IPV4_ADDR;
    this.netConfiguredByEnv = process.env.EASYTIER_NETWORK_LENGTH !== undefined;
    this.ipAutoAssigned = false;
    this.myInfo = null; // lazily initialized to avoid random in global scope
    this.sessionTtlMs = Number(process.env.EASYTIER_SESSION_TTL_MS || 3 * 60 * 1000);
    this.lastSessionCleanup = 0;

    this.pureP2PMode = (process.env.EASYTIER_DISABLE_RELAY === '1');
  }

  setTypes(types) {
    this.types = types;
  }

  ensureMyInfo() {
    if (this.myInfo) return this.myInfo;
    const myInfo = {
      peerId: MY_PEER_ID,
      instId: makeInstId(),
      cost: 1,
      version: 1,
      featureFlag: {
        isPublicServer: true,
        avoidRelayData: this.pureP2PMode,
        kcpInput: false,
        noRelayKcp: false
      },
      networkLength: Number(process.env.EASYTIER_NETWORK_LENGTH || 24),
      easytierVersion: process.env.EASYTIER_VERSION || "cf-ws-relay",
      lastUpdate: { seconds: Math.floor(Date.now() / 1000), nanos: 0 },
      hostname: process.env.EASYTIER_HOSTNAME || "PublicServer_WorkerRelay",
      udpStunInfo: 0,
      peerRouteId: randomU64String(),
      groups: [],
    };

    if (this.allowVirtualIP) {
      const ipEnv = process.env.EASYTIER_IPV4_ADDR;
      if (ipEnv) {
        myInfo.ipv4Addr = { addr: parseIpv4ToU32Be(ipEnv) };
        this.ipAutoAssigned = false;
      } else if (process.env.EASYTIER_AUTO_IPV4_ADDR === '1') {
        const lastOctet = (Number(MY_PEER_ID) % 250) + 2;
        myInfo.ipv4Addr = { addr: parseIpv4ToU32Be(`10.0.0.${lastOctet}`) };
        this.ipAutoAssigned = true;
      }
    }

    this.myInfo = myInfo;
    return this.myInfo;
  }

  bumpMyInfoVersion() {
    const myInfo = this.ensureMyInfo();
    myInfo.version = (myInfo.version || 0) + 1;
    myInfo.lastUpdate = { seconds: Math.floor(Date.now() / 1000), nanos: 0 };
  }

  // Called once with the persisted value before any socket is restored. Starting from at
  // least the current unix time keeps us above versions handed out by older deployments
  // that did not persist anything.
  restoreConnVersion(stored) {
    const floor = Math.floor(Date.now() / 1000);
    this.connVersion = Math.max(this.connVersion, Number(stored) || 0, floor);
  }

  bumpConnVersion() {
    if (!this.connVersion) this.restoreConnVersion(0);
    this.connVersion += 1;
    if (this.onConnVersionChange) {
      try {
        this.onConnVersionChange(this.connVersion);
      } catch (e) {
        console.error('persist conn version failed:', e);
      }
    }
    return this.connVersion;
  }

  setPublicServerFlag(isPublicServer) {
    const myInfo = this.ensureMyInfo();
    const next = !!isPublicServer;
    const prev = !!(myInfo.featureFlag && myInfo.featureFlag.isPublicServer);
    myInfo.featureFlag = {
      ...myInfo.featureFlag,
      isPublicServer: next,
    };
    if (next !== prev) {
      this.bumpMyInfoVersion();
    }
  }

  setPureP2PMode(enabled) {
    const next = !!enabled;
    if (next === this.pureP2PMode) return;
    this.pureP2PMode = next;
    const myInfo = this.ensureMyInfo();
    myInfo.featureFlag = {
      ...myInfo.featureFlag,
      avoidRelayData: this.pureP2PMode,
    };
    this.bumpMyInfoVersion();
  }

  isPureP2PMode() {
    return !!this.pureP2PMode;
  }

  _getPeersMap(groupKey, create = false) {
    const k = String(groupKey || '');
    let m = this.peersByGroup.get(k);
    if (!m && create) {
      m = new Map();
      this.peersByGroup.set(k, m);
    }
    return m;
  }

  _getPeerInfosMap(groupKey, create = false) {
    const k = String(groupKey || '');
    let m = this.peerInfosByGroup.get(k);
    if (!m && create) {
      m = new Map();
      this.peerInfosByGroup.set(k, m);
    }
    return m;
  }

  _getSession(groupKey, peerId, create = false) {
    const now = Date.now();
    if (now - this.lastSessionCleanup > Math.max(30_000, Math.min(this.sessionTtlMs / 2, 120_000))) {
      this.cleanupSessions(now);
    }
    const gk = String(groupKey || '');
    let g = this.routeSessions.get(gk);
    if (!g && create) {
      g = new Map();
      this.routeSessions.set(gk, g);
    }
    if (!g) return null;
    let s = g.get(peerId);
    if (!s && create) {
      s = {
        mySessionId: null,
        dstSessionId: null,
        weAreInitiator: false,
        peerInfoVerMap: new Map(),
        foreignNetVer: 0,
        lastTouch: Date.now(),
        lastConnBitmapSig: null,
      };
      g.set(peerId, s);
    }
    if (s) s.lastTouch = Date.now();
    return s;
  }

  cleanupSessions(nowTs = Date.now()) {
    this.lastSessionCleanup = nowTs;
    const ttl = this.sessionTtlMs;
    for (const [gk, m] of this.routeSessions.entries()) {
      for (const [pid, s] of m.entries()) {
        if (nowTs - (s.lastTouch || 0) > ttl) {
          m.delete(pid);
        }
      }
      if (m.size === 0) this.routeSessions.delete(gk);
    }
  }

  onRouteSessionAck(groupKey, peerId, theirSessionId, weAreInitiator) {
    const s = this._getSession(groupKey, peerId, true);
    if (s.dstSessionId !== theirSessionId) {
      s.peerInfoVerMap.clear();
      s.foreignNetVer = 0;
      s.lastConnBitmapSig = null;
    }
    s.dstSessionId = theirSessionId;
    if (typeof weAreInitiator === 'boolean') {
      s.weAreInitiator = weAreInitiator;
    }
  }

  // Returns the socket this one replaced (same peer reconnecting), if any.
  // opts.restoring: re-registering a socket that survived hibernation; the topology the
  // clients know has not changed, so the conn version is left alone.
  addPeer(peerId, ws, opts = {}) {
    const groupKey = ws && ws.groupKey ? String(ws.groupKey) : '';
    const peers = this._getPeersMap(groupKey, true);
    const prev = peers.get(peerId);
    peers.set(peerId, ws);
    if (!prev) {
      if (!opts.restoring) this.bumpConnVersion();
    } else if (prev !== ws) {
      // New connection means a new route session; the client resends its own info on it,
      // possibly with a lower version if it restarted, so forget the old one.
      const sessions = this.routeSessions.get(groupKey);
      if (sessions) sessions.delete(peerId);
      const infos = this._getPeerInfosMap(groupKey, false);
      if (infos) infos.delete(peerId);
    }
    return prev && prev !== ws ? prev : null;
  }

  removePeer(ws) {
    const peerId = ws && ws.peerId;
    const groupKey = ws && ws.groupKey ? String(ws.groupKey) : '';
    if (!peerId) return false;
    const peers = this._getPeersMap(groupKey, false);
    // A late close of a replaced socket must not evict the peer's current connection.
    if (!peers || peers.get(peerId) !== ws) return false;
    peers.delete(peerId);
    const infos = this._getPeerInfosMap(groupKey, false);
    if (infos) infos.delete(peerId);
    const sessions = this.routeSessions.get(groupKey);
    if (sessions) {
      sessions.delete(peerId);
      if (sessions.size === 0) this.routeSessions.delete(groupKey);
    }
    const pc = this.peerCenterStateByGroup.get(groupKey);
    if (pc) pc.globalPeerMap.delete(String(peerId));

    this.bumpConnVersion();

    if (peers.size === 0) {
      this.peersByGroup.delete(groupKey);
      this.peerInfosByGroup.delete(groupKey);
      this.peerCenterStateByGroup.delete(groupKey);
    }
    return true;
  }

  getPeerWs(peerId, groupKey) {
    const peers = this._getPeersMap(groupKey, false);
    return peers ? peers.get(peerId) : undefined;
  }

  listPeerIdsInGroup(groupKey) {
    const peers = this._getPeersMap(groupKey, false);
    return peers ? Array.from(peers.keys()) : [];
  }

  listPeersInGroup(groupKey) {
    const peers = this._getPeersMap(groupKey, false);
    return peers ? Array.from(peers.entries()) : [];
  }

  // Stores a live peer's own info. Infos of peers without a socket here are never kept,
  // otherwise a client resending its stale route table would resurrect departed peers.
  // Returns true when the stored info changed.
  updatePeerInfo(groupKey, peerId, info) {
    if (!this.getPeerWs(peerId, groupKey)) return false;
    const infos = this._getPeerInfosMap(groupKey, true);
    const prev = infos.get(peerId);
    if (prev && (prev.version || 0) >= (info.version || 0)) return false;
    infos.set(peerId, info);

    if (this.allowVirtualIP && !this.ipConfiguredByEnv && this.ipAutoAssigned) {
      const myInfo = this.ensureMyInfo();
      const peerIpv4 = info && info.ipv4Addr && typeof info.ipv4Addr.addr === 'number' ? (info.ipv4Addr.addr >>> 0) : null;
      const peerNetLen = info && (info.networkLength || info.network_length);
      const netLen = Number(peerNetLen || myInfo.networkLength || 24);
      if (peerIpv4 !== null && Number.isFinite(netLen) && netLen > 0) {
        const derived = deriveSameNetworkIpv4(peerIpv4, netLen, MY_PEER_ID);
        if (derived !== null) {
          let changed = false;
          if (!this.netConfiguredByEnv) {
            if (myInfo.networkLength !== netLen) {
              myInfo.networkLength = netLen;
              changed = true;
            }
          }
          const prevAddr = myInfo.ipv4Addr && typeof myInfo.ipv4Addr.addr === 'number'
            ? (myInfo.ipv4Addr.addr >>> 0)
            : null;
          if (prevAddr !== derived) {
            myInfo.ipv4Addr = { addr: derived };
            changed = true;
          }

          if (changed) {
            this.bumpMyInfoVersion();
            this.ipAutoAssigned = false;
          }
        }
      }
    }
    return true;
  }

  broadcastRouteUpdate(types, groupKey, excludePeerId, opts = {}) {
    const forceFull = opts.forceFull !== undefined ? !!opts.forceFull : true;
    if (groupKey !== undefined) {
      const peers = this._getPeersMap(groupKey, false);
      if (!peers) return;
      for (const [peerId, ws] of peers.entries()) {
        if (peerId === excludePeerId) continue;
        if (ws.readyState === WS_OPEN) {
          this.pushRouteUpdateTo(peerId, ws, types, { forceFull });
        }
      }
      return;
    }
    for (const [gk, peers] of this.peersByGroup.entries()) {
      for (const [peerId, ws] of peers.entries()) {
        if (peerId === excludePeerId) continue;
        if (ws.readyState === WS_OPEN) {
          this.pushRouteUpdateTo(peerId, ws, types, { forceFull });
        }
      }
    }
  }

  pushRouteUpdateTo(targetPeerId, ws, types, opts = {}) {
    const forceFull = !!opts.forceFull;
    const groupKey = ws && ws.groupKey ? String(ws.groupKey) : '';
    const session = this._getSession(groupKey, targetPeerId, true);
    const myInfo = this.ensureMyInfo();
    if (!ws.serverSessionId) {
      ws.serverSessionId = randomU64String();
    }
    session.mySessionId = ws.serverSessionId;
    const forceFullLocal = forceFull || !session.dstSessionId;

    // Only peers holding a live socket on this server are advertised. The server cannot
    // vouch for anything else, and advertising it is what kept departed peers alive.
    const livePeers = this.listPeerIdsInGroup(groupKey)
      .filter(p => p !== MY_PEER_ID)
      .sort((a, b) => Number(a) - Number(b));
    const relevantPeers = [MY_PEER_ID, ...livePeers];
    const infos = this._getPeerInfosMap(groupKey, false);

    const peerInfosItems = [];
    for (const pid of relevantPeers) {
      // Like EasyTier itself, never send the target its own info.
      if (pid === targetPeerId) continue;
      const info = (pid === MY_PEER_ID) ? myInfo : (infos && infos.get(pid));
      // Peers that have not synced their own info yet are only listed in the bitmap.
      if (!info) continue;
      const version = info.version ? info.version : 1;
      const prev = forceFullLocal ? 0 : (session.peerInfoVerMap.get(pid) || 0);
      if (forceFullLocal || version > prev) {
        peerInfosItems.push(info);
        session.peerInfoVerMap.set(pid, version);
      }
    }

    // Only the server's own row is authoritative: it lists every live peer and carries the
    // persisted connVersion, so a newer row without a departed peer always wins on clients.
    // The other rows say "connected to the server" with version 0, which clients store when
    // they know nothing better but never let override a row a peer reported itself.
    let connBitmap = null;
    if (!this.connVersion) this.restoreConnVersion(0);
    const N = relevantPeers.length;
    const bitmap = new Uint8Array(Math.ceil((N * N) / 8));
    const setBit = (row, col) => {
      const idx = row * N + col;
      bitmap[Math.floor(idx / 8)] |= (1 << (idx % 8));
    };
    const serverIdx = 0;
    for (let i = 1; i < N; i++) {
      setBit(serverIdx, i);
      setBit(i, serverIdx);
    }
    const peerIdVersions = relevantPeers.map((pid) => ({
      peerId: pid,
      version: pid === MY_PEER_ID ? this.connVersion : 0,
    }));
    const bitmapBuf = Buffer.from(bitmap);
    const sig = `${this.connVersion}|${relevantPeers.join(',')}`;
    if (forceFullLocal || sig !== session.lastConnBitmapSig) {
      session.lastConnBitmapSig = sig;
      connBitmap = { peerIds: peerIdVersions, bitmap: bitmapBuf };
    }

    const foreignNetworkInfos = (() => {
      const mode = (process.env.EASYTIER_HANDSHAKE_MODE || 'foreign').toLowerCase();
      if (mode === 'same' || mode === 'same_network') return null;
      const version = session.foreignNetVer + 1;
      session.foreignNetVer = version;
      return {
        infos: [{
          key: {
            peerId: MY_PEER_ID,
            networkName: process.env.EASYTIER_PUBLIC_SERVER_NETWORK_NAME || 'dev-websocket-relay'
          },
          value: {
            foreignPeerIds: livePeers,
            lastUpdate: { seconds: Math.floor(Date.now() / 1000), nanos: 0 },
            version,
            networkSecretDigest: Buffer.alloc(32),
            myPeerIdForThisNetwork: MY_PEER_ID
          }
        }]
      };
    })();

    const t = this.types;
    if (!t) {
      throw new Error('PeerManager types not set');
    }
    const rawPeerInfos = peerInfosItems.length > 0
      ? peerInfosItems.map(info => t.RoutePeerInfo.encode(info).finish())
      : null;

    const reqPayload = {
      myPeerId: MY_PEER_ID,
      mySessionId: ws.serverSessionId,
      isInitiator: !!ws.weAreInitiator,
      peerInfos: peerInfosItems.length > 0 ? { items: peerInfosItems } : null,
      rawPeerInfos: rawPeerInfos,
      connBitmap: connBitmap,
      foreignNetworkInfos: foreignNetworkInfos
    };

    const reqBytes = t.SyncRouteInfoRequest.encode(reqPayload).finish();
    const rpcRequestPayload = { request: reqBytes, timeoutMs: 5000 };
    const rpcRequestBytes = t.RpcRequest.encode(rpcRequestPayload).finish();

    const rpcReqPacket = {
      fromPeer: MY_PEER_ID,
      toPeer: targetPeerId,
      transactionId: Number(BigInt.asUintN(32, BigInt(randomU64String()))),
      descriptor: {
        domainName: ws.domainName || "public_server",
        protoName: 'OspfRouteRpc',
        serviceName: 'OspfRouteRpc',
        methodIndex: process.env.EASYTIER_OSPF_ROUTE_METHOD_INDEX ? Number(process.env.EASYTIER_OSPF_ROUTE_METHOD_INDEX) : 1
      },
      body: rpcRequestBytes,
      isRequest: true,
      totalPieces: 1,
      pieceIdx: 0,
      traceId: 0,
      compressionInfo: { algo: 1, acceptedAlgo: 1 }
    };

    const rpcPacketBytes = t.RpcPacket.encode(rpcReqPacket).finish();
    try {
      ws.send(wrapPacket(createHeader, MY_PEER_ID, targetPeerId, PacketType.RpcReq, rpcPacketBytes, ws));
    } catch (e) {
      // ignore
    }
  }
}
