// Native installer qualification only. Import the exact adapter extracted from
// the reviewed installer; never import private checkout source or bypass login.
import fs from 'node:fs/promises';
import { createReadStream, createWriteStream } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { createHash, randomUUID } from 'node:crypto';
import { createGunzip } from 'node:zlib';
import { pipeline } from 'node:stream/promises';
import { Readable } from 'node:stream';
import dgram from 'node:dgram';
import { setTimeout as sleep } from 'node:timers/promises';

const [installation, extracted, evidenceDirectory] = process.argv.slice(2);
if (process.platform !== 'win32' || process.arch !== 'x64')
  throw new Error('This qualification script requires a native Windows x64 host.');
if (!installation || !extracted || !evidenceDirectory)
  throw new Error('Usage: node windows-qemu-smoke.mjs INSTALL_DIR EXTRACTED_ASAR EVIDENCE_DIR');
const root = await fs.mkdtemp(path.join(path.resolve(evidenceDirectory), 'qemu-native-'));
const imageURL =
  'https://downloads.openwrt.org/releases/24.10.4/targets/x86/64/openwrt-24.10.4-x86-64-generic-ext4-combined.img.gz';
const publisherSha256 = '57f43d2a665646b0c45b909328704796db1777f85cc0c8ad51ec9b830d34ffc5';
const compressed = path.join(root, 'openwrt.img.gz');
const source = path.join(root, 'openwrt.img');
const digest = async (file) => {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(file)) hash.update(chunk);
  return hash.digest('hex');
};
const report = {
  schemaVersion: 1,
  platform: process.platform,
  arch: process.arch,
  adapter: 'installed app.asar/dist-electron/electron/qemu.js',
  imageURL,
  publisherSha256,
  passed: false,
  checks: {
    qemu: 'not-run',
    labNetworking: 'not-run',
    persistence: 'not-run',
    qemuShutdown: 'not-run',
  },
};
let engine;
const buffers = new Map();
const states = new Map();
const errors = new Map();
try {
  const response = await fetch(imageURL, {
    redirect: 'error',
    signal: AbortSignal.timeout(120000),
  });
  if (!response.ok || !response.body) throw new Error('Official OpenWrt image download failed.');
  let downloaded = 0;
  const bounded = async function* (chunks) {
    for await (const chunk of chunks) {
      downloaded += chunk.length;
      if (downloaded > 32 * 1024 * 1024) throw new Error('OpenWrt download exceeded its bound.');
      yield chunk;
    }
  };
  await pipeline(
    Readable.fromWeb(response.body),
    bounded,
    createWriteStream(compressed, { flags: 'wx' }),
  );
  if ((await digest(compressed)) !== publisherSha256)
    throw new Error('OpenWrt publisher SHA-256 mismatch.');
  let expanded = 0;
  const boundedDisk = async function* (chunks) {
    for await (const chunk of chunks) {
      expanded += chunk.length;
      if (expanded > 256 * 1024 * 1024)
        throw new Error('OpenWrt expanded disk exceeded its bound.');
      yield chunk;
    }
  };
  await pipeline(
    createReadStream(compressed),
    createGunzip(),
    boundedDisk,
    createWriteStream(source, { flags: 'wx' }),
  );
  const originalHash = await digest(source);
  const { QemuImages, QemuEngine } = await import(
    pathToFileURL(path.join(extracted, 'dist-electron/electron/qemu.js')).href
  );
  const { bundledQemuPaths } = await import(
    pathToFileURL(path.join(extracted, 'dist-electron/electron/bundled-qemu.js')).href
  );
  const runtime = bundledQemuPaths({
    packaged: true,
    resourcesPath: path.join(installation, 'resources'),
    developmentRoot: '',
    platform: 'win32',
    arch: 'x64',
  });
  const settings = { qemuPath: '', qemuImgPath: '' };
  const images = new QemuImages(path.join(root, 'managed'), runtime);
  const readiness = await images.checkRuntime(settings);
  if (!readiness.ready) throw new Error(readiness.message);
  const bundledManifest = JSON.parse(
    await fs.readFile(
      path.join(path.dirname(path.dirname(runtime.systemPath)), 'manifest.json'),
      'utf8',
    ),
  );
  if (
    readiness.systemVersion !== bundledManifest.version ||
    readiness.imgVersion !== bundledManifest.version
  )
    throw new Error('Native QEMU versions differ from the installer runtime manifest.');
  report.adapterSha256 = await digest(path.join(extracted, 'dist-electron/electron/qemu.js'));
  report.runtimeVersion = readiness.systemVersion;
  report.imageSha256 = originalHash;
  const image = await images.import(source, settings);
  engine = new QemuEngine(
    images,
    (id, running, error) => {
      states.set(id, running);
      if (error) errors.set(id, error);
    },
    ({ nodeId, data }) => buffers.set(nodeId, ((buffers.get(nodeId) ?? '') + data).slice(-200000)),
    () => {},
  );
  const node = (name) => ({
    id: randomUUID(),
    name,
    platform: 'qemu-x86_64',
    kind: 'router',
    x: 0,
    y: 0,
    ramMB: 256,
    qemu: { imageId: image.id, cpus: 1, diskBus: 'virtio', nicModel: 'virtio-net-pci', nat: false },
  });
  const one = node('OpenWrt native one'),
    two = node('OpenWrt native two');
  const project = randomUUID();
  const sockets = [dgram.createSocket('udp4'), dgram.createSocket('udp4')];
  try {
    await Promise.all(
      sockets.map(
        (socket) =>
          new Promise((resolve, reject) => {
            socket.once('error', reject);
            socket.bind(0, '127.0.0.1', resolve);
          }),
      ),
    );
    const ports = sockets.map((socket) => socket.address().port);
    report.distinctUdpPorts = ports[0] !== ports[1];
    for (const socket of sockets) await new Promise((resolve) => socket.close(resolve));
    const links = (n, index) => [
      { nodeId: n.id, port: 'eth1', local: ports[index], remote: ports[1 - index] },
    ];
    const wait = async (id, pattern, timeout = 180000) => {
      const deadline = Date.now() + timeout;
      while (Date.now() < deadline) {
        if (errors.has(id)) throw new Error(`Guest process failed: ${errors.get(id)}`);
        if (pattern.test(buffers.get(id) ?? '')) return;
        await sleep(200);
      }
      throw new Error('Guest serial command/readiness deadline expired.');
    };
    const ready = async (id) => {
      await wait(id, /Please press Enter|root@OpenWrt/);
      for (let n = 0; n < 180; n++) {
        if (/root@OpenWrt/.test(buffers.get(id) ?? '')) return;
        engine.sendConsole(id, '\r');
        await sleep(1000);
      }
      throw new Error('OpenWrt shell did not become ready.');
    };
    const command = async (id, text) => {
      const marker = randomUUID().replaceAll('-', '');
      buffers.set(id, '');
      engine.sendConsole(id, `( ${text} ); r=$?; printf '\\nLR_%s_RC=%s\\n' ${marker} "$r"\r`);
      await wait(id, new RegExp(`LR_${marker}_RC=\\d+\\r?\\n`), 30000);
      const output = buffers.get(id) ?? '';
      if (!output.includes(`LR_${marker}_RC=0`)) throw new Error('Guest command failed.');
      return output;
    };
    await engine.start(project, one, settings, links(one, 0));
    await engine.start(project, two, settings, links(two, 1));
    await Promise.all([ready(one.id), ready(two.id)]);
    report.checks.qemu = 'passed';
    await command(
      one.id,
      'ip addr flush dev eth1 && ip addr add 10.44.0.1/24 dev eth1 && ip link set eth1 up',
    );
    await command(
      two.id,
      'ip addr flush dev eth1 && ip addr add 10.44.0.2/24 dev eth1 && ip link set eth1 up',
    );
    const pingOne = await command(one.id, 'ping -c 3 -W 3 10.44.0.2');
    const pingTwo = await command(two.id, 'ping -c 3 -W 3 10.44.0.1');
    if (![pingOne, pingTwo].every((text) => /3 (?:packets )?received/.test(text)))
      throw new Error('Bidirectional guest packet forwarding failed.');
    report.bidirectionalPackets = { oneToTwo: 3, twoToOne: 3 };
    report.checks.labNetworking = 'passed';
    await command(one.id, "printf 'labsnracks-%s\\n' persistent > /root/labsnracks-smoke && sync");
    await engine.stop(one.id);
    if (states.get(two.id) !== true) throw new Error('Stopping one guest affected its peer.');
    await command(two.id, 'true');
    report.peerIsolation = true;
    buffers.delete(one.id);
    await engine.start(project, one, settings, links(one, 0));
    await ready(one.id);
    const persisted = await command(one.id, 'cat /root/labsnracks-smoke');
    if (!persisted.includes('labsnracks-persistent') || (await digest(source)) !== originalHash)
      throw new Error('Overlay persistence or original-image preservation failed.');
    report.checks.persistence = 'passed';
    report.originalImageUnchanged = true;
    await engine.stopAll();
    if (states.get(one.id) !== false || states.get(two.id) !== false)
      throw new Error('QEMU shutdown did not confirm both guests stopped.');
    report.checks.qemuShutdown = 'passed';
    report.passed = true;
  } finally {
    for (const socket of sockets) {
      try {
        socket.close();
      } catch {}
    }
  }
} catch (error) {
  report.error = error instanceof Error ? error.message : 'Native QEMU smoke failed.';
  const firstIncomplete = Object.keys(report.checks).find(
    (check) => report.checks[check] === 'not-run',
  );
  if (firstIncomplete) report.checks[firstIncomplete] = 'failed';
  process.exitCode = 1;
} finally {
  try {
    await engine?.stopAll();
  } catch {
    report.checks.qemuShutdown = 'failed';
    report.passed = false;
    process.exitCode = 1;
  }
  // Only sanitized results are uploaded. No raw console transcript, extracted
  // application, private profile, disk image or license is an artifact.
  await fs.writeFile(
    path.join(evidenceDirectory, 'qemu-native-evidence.json'),
    JSON.stringify(report, null, 2),
  );
  console.log(`Native QEMU smoke: ${report.passed ? 'passed' : 'failed'}`);
}
