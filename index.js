// ═══════════════════════════════════════════════════════════════
// minecraft-monitor.js
// Surveille des serveurs Minecraft (Java + Bedrock) toutes les 5 min.
// Dès qu'un serveur répond → webhook Discord → on ne le ping plus.
// Quand tous les serveurs ont répondu → pause infinie (pm2 le gère).
// ═══════════════════════════════════════════════════════════════

const net = require("net");
const dgram = require("dgram");
const https = require("https");
const http = require("http");
const { URL } = require("url");

// ─────────────────────────────────────────────
// ⚙️  CONFIGURATION
// ─────────────────────────────────────────────

const CONFIG = require("./config.json");

// ═══════════════════════════════════════════════════════════════
// PROTOCOLE JAVA — Server List Ping (TCP)
// ═══════════════════════════════════════════════════════════════

class JavaQuery {
  static encodeVarInt(value) {
    const bytes = [];
    while (true) {
      if ((value & ~0x7f) === 0) {
        bytes.push(value);
        return Buffer.from(bytes);
      }
      bytes.push((value & 0x7f) | 0x80);
      value >>>= 7;
    }
  }

  static decodeVarInt(buffer, offset = 0) {
    let value = 0;
    let length = 0;
    let currentByte;
    do {
      if (offset + length >= buffer.length) throw new Error("VarInt incomplet");
      currentByte = buffer[offset + length];
      value |= (currentByte & 0x7f) << (length * 7);
      length++;
      if (length > 5) throw new Error("VarInt trop long");
    } while ((currentByte & 0x80) !== 0);
    return { value, bytesRead: length };
  }

  static buildHandshakePacket(host, port) {
    const packetId = this.encodeVarInt(0x00);
    const protocolVersion = this.encodeVarInt(767);
    const hostBuf = Buffer.from(host, "utf-8");
    const hostLen = this.encodeVarInt(hostBuf.length);
    const portBuf = Buffer.alloc(2);
    portBuf.writeUInt16BE(port);
    const nextState = this.encodeVarInt(1);

    const data = Buffer.concat([
      packetId,
      protocolVersion,
      hostLen,
      hostBuf,
      portBuf,
      nextState,
    ]);
    return Buffer.concat([this.encodeVarInt(data.length), data]);
  }

  static buildStatusRequest() {
    const packetId = this.encodeVarInt(0x00);
    return Buffer.concat([this.encodeVarInt(packetId.length), packetId]);
  }

  static query(host, port, timeout) {
    return new Promise((resolve, reject) => {
      const socket = new net.Socket();
      let buf = Buffer.alloc(0);
      let done = false;
      const t0 = Date.now();

      socket.setTimeout(timeout);

      const finish = (err, result) => {
        if (done) return;
        done = true;
        socket.destroy();
        err ? reject(err) : resolve(result);
      };

      socket.on("connect", () => {
        socket.write(this.buildHandshakePacket(host, port));
        socket.write(this.buildStatusRequest());
      });

      socket.on("data", (chunk) => {
        buf = Buffer.concat([buf, chunk]);
        try {
          const pktLen = this.decodeVarInt(buf, 0);
          const totalNeeded = pktLen.value + pktLen.bytesRead;
          if (buf.length < totalNeeded) return; // attend plus de données

          let off = pktLen.bytesRead;
          const pktId = this.decodeVarInt(buf, off);
          off += pktId.bytesRead;

          if (pktId.value === 0x00) {
            const strLen = this.decodeVarInt(buf, off);
            off += strLen.bytesRead;
            const json = buf.slice(off, off + strLen.value).toString("utf-8");
            const info = JSON.parse(json);
            info._latency = Date.now() - t0;
            finish(null, info);
          }
        } catch {
          /* données incomplètes */
        }
      });

      socket.on("timeout", () => finish(new Error("Timeout")));
      socket.on("error", (e) => finish(new Error(e.message)));
      socket.on("close", () => finish(new Error("Connexion fermée")));
      socket.connect(port, host);
    });
  }
}

// ═══════════════════════════════════════════════════════════════
// PROTOCOLE BEDROCK — RakNet Unconnected Ping (UDP)
// ═══════════════════════════════════════════════════════════════

class BedrockQuery {
  static MAGIC = Buffer.from([
    0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe, 0xfd, 0xfd, 0xfd, 0xfd,
    0x12, 0x34, 0x56, 0x78,
  ]);

  static buildPing() {
    const buf = Buffer.alloc(33);
    let off = 0;
    buf.writeUInt8(0x01, off);
    off += 1;
    buf.writeBigInt64BE(BigInt(Date.now()), off);
    off += 8;
    this.MAGIC.copy(buf, off);
    off += 16;
    buf.writeBigInt64BE(BigInt(Math.floor(Math.random() * 2 ** 48)), off);
    return buf;
  }

  static parsePong(buf) {
    let off = 0;
    const id = buf.readUInt8(off);
    off += 1;
    if (id !== 0x1c) throw new Error(`Paquet inattendu 0x${id.toString(16)}`);
    off += 8; // ping time
    off += 8; // server guid
    const magic = buf.slice(off, off + 16);
    off += 16;
    if (!magic.equals(this.MAGIC)) throw new Error("Magic invalide");
    const len = buf.readUInt16BE(off);
    off += 2;
    const raw = buf.slice(off, off + len).toString("utf-8");
    const f = raw.split(";");

    return {
      raw,
      edition: f[0] || null,
      motd: { line1: f[1] || null, line2: f[7] || null },
      protocol: { version: parseInt(f[2]) || null, name: f[3] || null },
      players: { online: parseInt(f[4]) || 0, max: parseInt(f[5]) || 0 },
      serverId: f[6] || null,
      gamemode: { name: f[8] || null, id: parseInt(f[9]) ?? null },
      port: { ipv4: parseInt(f[10]) || null, ipv6: parseInt(f[11]) || null },
    };
  }

  static query(host, port, timeout) {
    return new Promise((resolve, reject) => {
      const socket = dgram.createSocket("udp4");
      let done = false;
      const t0 = Date.now();

      const timer = setTimeout(() => finish(new Error("Timeout")), timeout);

      const finish = (err, result) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        try {
          socket.close();
        } catch {}
        err ? reject(err) : resolve(result);
      };

      socket.on("message", (msg) => {
        try {
          const info = this.parsePong(msg);
          info._latency = Date.now() - t0;
          finish(null, info);
        } catch (e) {
          finish(e);
        }
      });

      socket.on("error", (e) => finish(new Error(e.message)));

      const pkt = this.buildPing();
      socket.send(pkt, 0, pkt.length, port, host, (err) => {
        if (err) finish(new Error(err.message));
      });
    });
  }
}

// ═══════════════════════════════════════════════════════════════
// WEBHOOK DISCORD
// ═══════════════════════════════════════════════════════════════

function stripColors(text) {
  if (typeof text !== "string") return String(text ?? "");
  return text.replace(/§[0-9a-fk-or]/gi, "");
}

function extractMotd(desc) {
  if (typeof desc === "string") return stripColors(desc);
  if (typeof desc === "object") {
    let text = desc.text || "";
    if (Array.isArray(desc.extra)) {
      for (const p of desc.extra) text += p.text || "";
    }
    return stripColors(text);
  }
  return String(desc);
}

/**
 * Construit l'embed Discord pour un serveur Java
 */
function buildJavaEmbed(server, info) {
  const motd = info.description ? extractMotd(info.description) : "—";
  const playerList =
    (info.players?.sample || [])
      .slice(0, 15)
      .map((p) => `\`${stripColors(p.name)}\``)
      .join(", ") || "Aucun affiché";

  const embed = {
    title: `☕ ${server.name} est EN LIGNE !`,
    color: 0x55ff55,
    fields: [
      {
        name: "🌐 Adresse",
        value: `\`${server.host}:${server.port}\``,
        inline: true,
      },
      {
        name: "📋 Version",
        value: `${info.version?.name || "?"}`,
        inline: true,
      },
      {
        name: "🔢 Protocole",
        value: `${info.version?.protocol || "?"}`,
        inline: true,
      },
      {
        name: "👥 Joueurs",
        value: `**${info.players?.online ?? "?"}** / ${info.players?.max ?? "?"}`,
        inline: true,
      },
      { name: "⏱️ Latence", value: `${info._latency} ms`, inline: true },
      {
        name: "🔒 Chat sécurisé",
        value: info.enforcesSecureChat ? "Oui" : "Non",
        inline: true,
      },
      { name: "💬 MOTD", value: `\`\`\`${motd.slice(0, 1000)}\`\`\`` },
      { name: "📜 Joueurs visibles", value: playerList.slice(0, 1024) },
    ],
    footer: { text: "Minecraft Java • Server List Ping" },
    timestamp: new Date().toISOString(),
  };

  // ═══ CORRECTION : Discord n'accepte PAS les data URI dans thumbnail ═══
  // On n'ajoute le thumbnail que si c'est une vraie URL (http/https)
  if (info.favicon && info.favicon.startsWith("http")) {
    embed.thumbnail = { url: info.favicon };
  }

  return embed;
}

/**
 * Construit l'embed Discord pour un serveur Bedrock
 */
function buildBedrockEmbed(server, info) {
  return {
    title: `🪨 ${server.name} est EN LIGNE !`,
    color: 0x00aaff, // bleu
    fields: [
      {
        name: "🌐 Adresse",
        value: `\`${server.host}:${server.port}\``,
        inline: true,
      },
      { name: "📋 Édition", value: `${info.edition || "?"}`, inline: true },
      {
        name: "🎮 Version",
        value: `${info.protocol?.name || "?"}`,
        inline: true,
      },
      {
        name: "🔢 Protocole",
        value: `${info.protocol?.version || "?"}`,
        inline: true,
      },
      {
        name: "👥 Joueurs",
        value: `**${info.players?.online ?? "?"}** / ${info.players?.max ?? "?"}`,
        inline: true,
      },
      {
        name: "🎯 Mode de jeu",
        value: `${info.gamemode?.name || "?"} (${info.gamemode?.id ?? "?"})`,
        inline: true,
      },
      { name: "⏱️ Latence", value: `${info._latency} ms`, inline: true },
      {
        name: "🆔 Server ID",
        value: `\`${info.serverId || "—"}\``,
        inline: true,
      },
      {
        name: "💬 MOTD",
        value: `\`\`\`${stripColors(info.motd?.line1 || "—")}\n${stripColors(info.motd?.line2 || "")}\`\`\``,
      },
    ],
    footer: { text: "Minecraft Bedrock • RakNet Ping" },
    timestamp: new Date().toISOString(),
  };
}

/**
 * Envoie un webhook Discord (sans dépendance externe)
 */
function sendWebhook(webhookUrl, payload) {
  return new Promise((resolve, reject) => {
    const url = new URL(webhookUrl);
    const data = JSON.stringify(payload);
    const lib = url.protocol === "https:" ? https : http;

    const req = lib.request(
      {
        hostname: url.hostname,
        port: url.port || (url.protocol === "https:" ? 443 : 80),
        path: url.pathname + url.search,
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(data),
        },
      },
      (res) => {
        let body = "";
        res.on("data", (c) => (body += c));
        res.on("end", () => {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            resolve(body);
          } else if (res.statusCode === 429) {
            // Rate limit — retry après le délai indiqué
            const retryAfter = JSON.parse(body)?.retry_after || 5;
            log(`⏳ Rate limit Discord, retry dans ${retryAfter}s...`);
            setTimeout(
              () =>
                sendWebhook(webhookUrl, payload).then(resolve).catch(reject),
              retryAfter * 1000,
            );
          } else {
            reject(new Error(`Discord HTTP ${res.statusCode}: ${body}`));
          }
        });
      },
    );

    req.on("error", reject);
    req.write(data);
    req.end();
  });
}

// ═══════════════════════════════════════════════════════════════
// MOTEUR DE MONITORING
// ═══════════════════════════════════════════════════════════════

function log(msg) {
  const ts = new Date().toISOString();
  console.log(`[${ts}] ${msg}`);
}

async function queryServer(server, timeout) {
  if (server.type === "java") {
    return JavaQuery.query(server.host, server.port, timeout);
  }
  if (server.type === "bedrock") {
    return BedrockQuery.query(server.host, server.port, timeout);
  }
  throw new Error(`Type inconnu : ${server.type}`);
}

async function notifyDiscord(server, info) {
  const embed =
    server.type === "java"
      ? buildJavaEmbed(server, info)
      : buildBedrockEmbed(server, info);

  const payload = {
    username: "🟢 Minecraft Monitor",
    avatar_url: "https://i.imgur.com/AfFp7pu.png",
    embeds: [embed],
  };

  await sendWebhook(CONFIG.webhookUrl, payload);
}

async function runCycle(pendingServers) {
  log(`🔄 Cycle de ping — ${pendingServers.length} serveur(s) restant(s)`);

  // On copie la liste pour pouvoir la modifier pendant l'itération
  const toRemove = [];

  for (const server of pendingServers) {
    const label = `[${server.type.toUpperCase()}] ${server.name} (${server.host}:${server.port})`;

    try {
      log(`  📡 Ping ${label}...`);
      const info = await queryServer(server, CONFIG.queryTimeout);

      log(`  ✅ ${label} → EN LIGNE (${info._latency}ms)`);

      // Envoyer le webhook
      try {
        await notifyDiscord(server, info);
        log(`  📨 Webhook envoyé pour ${server.name}`);
      } catch (webhookErr) {
        log(`  ⚠️  Webhook échoué pour ${server.name}: ${webhookErr.message}`);
        // On considère quand même le serveur comme détecté
      }

      toRemove.push(server);
    } catch (err) {
      log(`  ❌ ${label} → ${err.message}`);
    }
  }

  // Retirer les serveurs qui ont répondu
  for (const server of toRemove) {
    const idx = pendingServers.indexOf(server);
    if (idx !== -1) pendingServers.splice(idx, 1);
  }

  return pendingServers.length;
}

async function main() {
  log("═".repeat(60));
  log("🚀 Minecraft Monitor démarré");
  log(`📋 ${CONFIG.servers.length} serveur(s) à surveiller`);
  log(`⏱️  Intervalle : ${CONFIG.intervalMs / 1000}s`);
  log(`🔗 Webhook : ${CONFIG.webhookUrl.slice(0, 60)}...`);
  log("═".repeat(60));

  // Liste mutable des serveurs pas encore détectés
  const pending = [...CONFIG.servers];

  // Boucle principale
  while (true) {
    const remaining = await runCycle(pending);

    if (remaining === 0) {
      log("");
      log("═".repeat(60));
      log("🎉 Tous les serveurs ont été détectés !");
      log("💤 Passage en pause infinie (pm2 gère le restart)");
      log("═".repeat(60));

      // Pause infinie — le process reste vivant mais ne fait rien
      // pm2 peut le redémarrer via cron ou restart policy
      await new Promise(() => {});
      // On n'atteint jamais ici
    }

    log(
      `⏳ Prochain cycle dans ${CONFIG.intervalMs / 1000}s — ${remaining} serveur(s) restant(s)\n`,
    );
    await sleep(CONFIG.intervalMs);
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ─────────────────────────────────────────────
// Gestion propre des signaux
// ─────────────────────────────────────────────

process.on("SIGINT", () => {
  log("🛑 SIGINT reçu — arrêt propre");
  process.exit(0);
});

process.on("SIGTERM", () => {
  log("🛑 SIGTERM reçu — arrêt propre");
  process.exit(0);
});

process.on("uncaughtException", (err) => {
  log(`💥 Exception non gérée : ${err.message}`);
  log(err.stack);
  // On continue quand même
});

process.on("unhandledRejection", (reason) => {
  log(`💥 Promise rejetée non gérée : ${reason}`);
});

// ─────────────────────────────────────────────
// Lancement
// ─────────────────────────────────────────────
main().catch((err) => {
  log(`💥 Erreur fatale : ${err.message}`);
  process.exit(1);
});
