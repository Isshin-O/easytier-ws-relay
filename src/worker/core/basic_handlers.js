import { MAGIC, VERSION, MY_PEER_ID, PacketType } from './constants.js';
import { createHeader } from './packet.js';
import { wrapPacket, randomU64String } from './crypto.js';

const WS_OPEN = (typeof WebSocket !== 'undefined' && WebSocket.OPEN) ? WebSocket.OPEN : 1;

export function handleHandshake(ws, header, payload, types) {
  try {
    const req = types.HandshakeRequest.decode(payload);
    try {
      const dig = req.networkSecretDigrest ? Buffer.from(req.networkSecretDigrest) : Buffer.alloc(0);
      console.log(`Handshake networkSecretDigest(hex)=${dig.toString('hex')}`);
    } catch (_) {
      // ignore
    }

    if (req.magic !== MAGIC) {
      console.error('Invalid magic');
      ws.close();
      return;
    }

    const pm = ws.peerManager;
    // Record the first registered digest per network name; later mismatched digest will be rejected
    const networkDigestRegistry = pm.networkDigestRegistry;
    const clientNetworkName = req.networkName || '';
    const clientDigest = req.networkSecretDigrest ? Buffer.from(req.networkSecretDigrest) : Buffer.alloc(0);
    const digestHex = clientDigest.toString('hex');
    const existingDigest = networkDigestRegistry.get(clientNetworkName);
    if (existingDigest && existingDigest !== digestHex) {
      console.error(`Rejecting handshake from ${req.myPeerId}: digest mismatch for network "${clientNetworkName}" (existing=${existingDigest}, incoming=${digestHex})`);
      ws.close();
      return;
    }
    if (!existingDigest) {
      networkDigestRegistry.set(clientNetworkName, digestHex);
    }
    const groupDigest = networkDigestRegistry.get(clientNetworkName) || '';
    const groupKey = `${clientNetworkName}:${groupDigest}`;
    const serverNetworkName = process.env.EASYTIER_PUBLIC_SERVER_NETWORK_NAME || 'public_server';
    const digest = new Uint8Array(32);

    ws.domainName = clientNetworkName;

    const respPayload = {
      magic: MAGIC,
      myPeerId: MY_PEER_ID,
      version: VERSION,
      features: ["node-server-v1"],
      networkName: serverNetworkName,
      networkSecretDigrest: digest
    };

    ws.groupKey = groupKey;
    ws.peerId = req.myPeerId;
    ws.serializeAttachment?.({
      ...(ws.deserializeAttachment?.() || {}),
      peerId: ws.peerId,
      groupKey: ws.groupKey,
      domainName: ws.domainName,
    });
    // The peer's own info arrives with its first SyncRouteInfo; until then it is only
    // listed in the conn bitmap.
    const replaced = pm.addPeer(req.myPeerId, ws);
    if (replaced) {
      // Same peer reconnected: drop the old socket. Its close event is then a no-op
      // because removePeer only removes the socket currently registered for the peer.
      try { replaced.close(1000, 'replaced by new connection'); } catch (_) { }
    }
    pm.setPublicServerFlag(true);
    ws.crypto = { enabled: false };

    const respBuffer = types.HandshakeRequest.encode(respPayload).finish();
    const respHeader = createHeader(MY_PEER_ID, req.myPeerId, PacketType.HandShake, respBuffer.length);
    ws.send(Buffer.concat([respHeader, Buffer.from(respBuffer)]));
    if (!ws.serverSessionId) {
      ws.serverSessionId = randomU64String();
    }
    if (ws.weAreInitiator === undefined) {
      ws.weAreInitiator = false;
    }

    setTimeout(() => {
      try {
        if (ws.readyState === WS_OPEN) {
          pm.pushRouteUpdateTo(req.myPeerId, ws, types, { forceFull: true });
          pm.broadcastRouteUpdate(types, ws.groupKey, req.myPeerId, { forceFull: true });
        }
      } catch (e) {
        console.error(`Failed to push initial route update to ${req.myPeerId}:`, e.message);
      }
    }, 50);

  } catch (e) {
    console.error('Handshake error:', e);
    ws.close();
  }
}

export function handlePing(ws, header, payload) {
  const msg = wrapPacket(createHeader, MY_PEER_ID, header.fromPeerId, PacketType.Pong, payload, ws);
  ws.send(msg);
}

export function handleForwarding(sourceWs, header, fullMessage, types) {
  const targetPeerId = header.toPeerId;
  const pm = sourceWs.peerManager;
  const groupKey = sourceWs && sourceWs.groupKey;
  // Peers behind another peer are reached through that peer, which relays like any node.
  const targetWs = pm.getPeerWs(targetPeerId, groupKey) || pm.nextHopWs(targetPeerId, groupKey);

  // Never bounce a packet back where it came from.
  if (targetWs && targetWs !== sourceWs && targetWs.readyState === WS_OPEN) {
    const srcGroup = sourceWs && sourceWs.groupKey;
    const dstGroup = targetWs && targetWs.groupKey;
    if (srcGroup && dstGroup && srcGroup !== dstGroup) {
      return;
    }
    try {
      targetWs.send(fullMessage);
    } catch (e) {
      console.error(`Forward to ${targetPeerId} failed: ${e.message}`);
      pm.removePeer(targetWs);
      try {
        pm.broadcastRouteUpdate(types, srcGroup);
      } catch (err) {
        console.error(`Broadcast after forward failure failed: ${err.message}`);
      }
    }
  } else {
  }
}
