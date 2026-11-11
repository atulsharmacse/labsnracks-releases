// Native installer qualification only. Import the exact adapter extracted from
// the reviewed installer; never import private checkout source or bypass login.
import fs from 'node:fs/promises';
import { createReadStream, createWriteStream } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { createHash, randomUUID } from 'node:crypto';
import { decodePinnedGzipImage } from './gzip-image.mjs';
import { pipeline } from 'node:stream/promises';
import https from 'node:https';
import dgram from 'node:dgram';
import { setTimeout as sleep } from 'node:timers/promises';
import { execFile } from 'node:child_process';
import { stripVTControlCharacters } from 'node:util';

const [installation, extracted, evidenceDirectory] = process.argv.slice(2);
if (process.platform !== 'win32' || process.arch !== 'x64')
  throw new Error('This qualification script requires a native Windows x64 host.');
if (process.argv[2] === '--probe-runtime') {
  const binary = process.argv[3],
    directory = process.argv[4];
  if (!binary || !directory)
    throw new Error('Runtime probe requires binary and evidence directory.');
  const name = path.basename(binary);
  if (!['qemu-system-x86_64.exe', 'qemu-img.exe', 'dynamips.exe'].includes(name))
    throw new Error('Unsupported runtime probe binary.');
  const started = Date.now();
  // Match QemuImages.checkRuntime's execFile transport and 30-second deadline.
  const result = await new Promise((resolve) => {
    execFile(
      binary,
      ['--version'],
      { timeout: 30000, maxBuffer: 16384 },
      (error, stdout, stderr) => {
        const code = error ? error.code : 0;
        const pattern = name.startsWith('dynamips')
          ? /Dynamips|Cisco Router Simulation Platform/i
          : name.startsWith('qemu-img')
            ? /qemu-img version/i
            : /QEMU emulator version/i;
        resolve({
          binary: name,
          transport: 'node.execFile',
          timeoutMs: 30000,
          elapsedMs: Date.now() - started,
          exitCode: code,
          killed: !!error?.killed,
          passed:
            (code === 0 || (name.startsWith('dynamips') && code === 1)) &&
            pattern.test(stdout + stderr),
          stdout,
          stderr,
        });
      },
    );
  });
  const { stdout, stderr, ...metadata } = result;
  await fs.writeFile(path.join(directory, name + '.node.stdout.txt'), stdout);
  await fs.writeFile(path.join(directory, name + '.node.stderr.txt'), stderr);
  await fs.writeFile(
    path.join(directory, name + '.node-probe.json'),
    JSON.stringify(metadata, null, 2),
  );
  console.log(`Adapter-faithful runtime probe ${name}: ${metadata.passed ? 'passed' : 'failed'}`);
  process.exit(metadata.passed ? 0 : 1);
}
if (!installation || !extracted || !evidenceDirectory)
  throw new Error('Usage: node windows-qemu-smoke.mjs INSTALL_DIR EXTRACTED_ASAR EVIDENCE_DIR');
// 0.2.1 diagnosis works around its known CR-discarding transport. Final
// rebuilt candidates must prove raw xterm Enter through their installed fix.
const diagnosticCrLf =
  process.env.LABSNRACKS_DIAGNOSTIC_PATCH === 'true' &&
  process.env.LABSNRACKS_EXPECTED_VERSION === '0.2.1';
const enter = diagnosticCrLf ? '\r\n' : '\r';
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
  diagnosticOnly: process.env.LABSNRACKS_DIAGNOSTIC_PATCH === 'true',
  serialInput: diagnosticCrLf
    ? 'CRLF paced 10ms diagnostic workaround'
    : 'raw CR through installed adapter',
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
let lastCommand;
const buffers = new Map();
const states = new Map();
const errors = new Map();
try {
  // Raw publisher bytes: fetch transparently decodes Content-Encoding and
  // can turn a .gz asset into an ambiguous second decompression on this host.
  const response = await new Promise((resolve, reject) => {
    const request = https.get(
      imageURL,
      { signal: AbortSignal.timeout(120000), headers: { 'Accept-Encoding': 'identity' } },
      resolve,
    );
    request.once('error', reject);
  });
  if (response.statusCode !== 200) {
    response.destroy();
    throw new Error('Official OpenWrt image download failed or redirected.');
  }
  const contentLength = response.headers['content-length'];
  if (
    contentLength !== undefined &&
    (!/^\d+$/.test(contentLength) || Number(contentLength) > 32 * 1024 * 1024)
  ) {
    response.destroy();
    throw new Error('Official OpenWrt image download exceeds its bound.');
  }
  let downloaded = 0;
  const bounded = async function* (chunks) {
    for await (const chunk of chunks) {
      downloaded += chunk.length;
      if (downloaded > 32 * 1024 * 1024) throw new Error('OpenWrt download exceeded its bound.');
      yield chunk;
    }
  };
  await pipeline(response, bounded, createWriteStream(compressed, { flags: 'wx' }));
  if ((await digest(compressed)) !== publisherSha256)
    throw new Error('OpenWrt publisher SHA-256 mismatch.');
  report.imageDecoding = await decodePinnedGzipImage(compressed, source, publisherSha256);
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
      { nodeId: n.id, port: 'eth2', local: ports[index], remote: ports[1 - index] },
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
    const send = async (id, input) => {
      if (diagnosticCrLf) {
        for (const character of input) {
          engine.sendConsole(id, character);
          await sleep(10);
        }
      } else engine.sendConsole(id, input);
    };
    const ready = async (id) => {
      await wait(id, /Please press Enter|root@OpenWrt/);
      for (let n = 0; n < 180; n++) {
        if (/root@OpenWrt/.test(buffers.get(id) ?? '')) return;
        await send(id, enter);
        await sleep(1000);
      }
      throw new Error('OpenWrt shell did not become ready.');
    };
    const command = async (id, text) => {
      const marker = randomUUID().replaceAll('-', '');
      buffers.set(id, '');
      lastCommand = { id, marker, text };
      await send(id, `( ${text} ); r=$?; printf '\\nLR_%s_RC=%s_END\\n' ${marker} "$r"${enter}`);
      const proof = new RegExp(`LR_${marker}_RC=(\\d+)_END`);
      await wait(id, proof, 30000);
      const output = buffers.get(id) ?? '';
      if (proof.exec(output)?.[1] !== '0') throw new Error('Guest command failed.');
      report.completedCommands = (report.completedCommands ?? 0) + 1;
      return output;
    };
    report.stage = 'start-first-guest';
    await engine.start(project, one, settings, links(one, 0));
    report.stage = 'start-second-guest';
    await engine.start(project, two, settings, links(two, 1));
    report.stage = 'serial-shell-readiness';
    await Promise.all([ready(one.id), ready(two.id)]);
    report.checks.qemu = 'passed';
    report.stage = 'address-and-packet-proof';
    await command(
      one.id,
      'ip addr flush dev eth2 && ip addr add 10.44.0.1/24 dev eth2 && ip link set eth2 up',
    );
    await command(
      two.id,
      'ip addr flush dev eth2 && ip addr add 10.44.0.2/24 dev eth2 && ip link set eth2 up',
    );
    const pingOne = await command(one.id, 'ping -c 3 -W 3 10.44.0.2');
    const pingTwo = await command(two.id, 'ping -c 3 -W 3 10.44.0.1');
    if (![pingOne, pingTwo].every((text) => /3 (?:packets )?received/.test(text)))
      throw new Error('Bidirectional guest packet forwarding failed.');
    report.bidirectionalPackets = { oneToTwo: 3, twoToOne: 3 };
    report.checks.labNetworking = 'passed';
    report.stage = 'overlay-persistence';
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
  if (lastCommand) {
    const observed = buffers.get(lastCommand.id) ?? '';
    const flat = stripVTControlCharacters(observed).replace(/[\r\n]/g, '');
    report.commandObservation = {
      echoedMarkerArgument: flat.includes(lastCommand.marker),
      echoedCommand: flat.includes(lastCommand.text),
      returnValues: [
        ...observed.matchAll(new RegExp(`LR_${lastCommand.marker}_RC=(\\d+)_END`, 'g')),
      ].map((m) => m[1]),
      shellError: /not found|syntax error|unexpected/.test(flat),
      carriageReturns: (observed.match(/\r/g) ?? []).length,
      lineFeeds: (observed.match(/\n/g) ?? []).length,
    };
  }
  report.serialMarkers = [...buffers.values()].map((text) => ({
    bufferedCharacters: text.length,
    pressEnter: /Please press Enter/.test(text),
    rootPrompt: /root@/.test(text),
    openWrt: /OpenWrt/.test(text),
    busyBox: /BusyBox/.test(text),
    loginPrompt: /login:/.test(text),
    passwordPrompt: /[Pp]assword:/.test(text),
    kernelPanic: /Kernel panic/.test(text),
  }));
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
