// verify 服务：一次运行、退出码收尾。
//   1) 重组规则单元/集成测试（lib 全链路）
//   2) 页面构建检查（index.html 引用的静态资源齐备、ESM 可解析）
//   3) HTTP 冒烟：拉起 app，验证 /healthz，并通过 HTTP 拉取本题捕获样例做端到端复核
import { spawn } from 'node:child_process';
import { readFile, access } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';

import { analyze, AnalysisError } from '../lib/analyze.js';
import { decodeBase64Classic } from '../lib/base64.js';
import { computeIpChecksum } from '../lib/checksum.js';
import {
  arpFrame, commandFrame, eth, fragmentPayload, ip, ipFragment, ipv4Packet,
  makeSession, pcap, tcp,
} from './builder.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');

let passed = 0;
let failed = 0;
const failures = [];

function ok(name, cond, detail = '') {
  if (cond) { passed += 1; }
  else { failed += 1; failures.push(`${name}${detail ? ` — ${detail}` : ''}`); }
}
function eq(name, actual, expected) {
  const a = JSON.stringify(actual);
  const e = JSON.stringify(expected);
  ok(name, a === e, `期望 ${e}，实得 ${a}`);
}
function expectCode(name, fn, code) {
  try {
    fn();
    ok(name, false, `未抛出，期望 ${code}`);
  } catch (e) {
    ok(name, e instanceof AnalysisError && e.code === code,
      `期望 ${code}，实得 ${e.code ?? e.constructor.name}: ${e.message}`);
  }
}
function b64(buf) { return buf.toString('base64'); }

const T = { srcIp: '10.0.0.10', dstIp: '10.0.0.20', srcPort: 5100, dstPort: 8080 };
const req = (buf, extra = {}) => ({ ...T, pcapBase64: b64(buf), ...extra });

// ---------- 1. Base64 ----------
{
  eq('base64: 标准解码', [...decodeBase64Classic('SGVsbG8=')], [...Buffer.from('Hello')]);
  eq('base64: 容忍空白换行', [...decodeBase64Classic('SGVs\nbG8= ')], [...Buffer.from('Hello')]);
  expectCode('base64: URL-safe 字符拒绝', () => decodeBase64Classic('SGVsbG8-SG'), 'BAD_BASE64');
  expectCode('base64: 错误填充拒绝', () => decodeBase64Classic('SGVsbG8=='), 'BAD_BASE64');
  expectCode('base64: 空串拒绝', () => decodeBase64Classic('  \n '), 'BAD_BASE64');
  expectCode('base64: 长度非 4 倍数拒绝', () => decodeBase64Classic('AAA'), 'BAD_BASE64');
  // 非规范尾组（多余置位位）也拒绝：例如 'AB==' 解码单字节但 12 低位非零
  expectCode('base64: 非规范置位位拒绝', () => decodeBase64Classic('AB=='), 'BAD_BASE64');
}

// ---------- 2. PCAP 容器 ----------
{
  expectCode('pcap: 魔数错误（pcapng 等）拒绝',
    () => analyze(req(Buffer.concat([Buffer.alloc(24, 0), Buffer.from([1])]))), 'BAD_PCAP_MAGIC');
  const tiny = pcap([Buffer.alloc(60)]);
  const cut = tiny.subarray(0, tiny.length - 4);
  expectCode('pcap: 尾部截断拒绝', () => analyze(req(cut)), 'TRUNCATED_CAPTURE');
  // 大端序 PCAP 必须正常
  const s = makeSession({ commands: ['X'] });
  const be = pcap([s.syn(), s.data(0, 3), s.fin(3)], { le: false });
  let rBe = null;
  try { rBe = analyze(req(be)); } catch (e) { ok('pcap: 大端序可解析', false, e.message); }
  if (rBe) eq('pcap: 大端序指令重建', rBe.commands.map((c) => c.text), ['X']);
}

// ---------- 3. 链路层 / IP 校验和 ----------
{
  const s = makeSession({ commands: ['PING'] });
  const frames = [s.syn(), s.data(0, 6), s.fin(6)];
  // 802.3 长度型帧（ethertype 位置 <= 1500）不是 Ethernet II
  const lengthFrame = Buffer.from(eth(Buffer.alloc(40), 0x0028));
  expectCode('link: 802.3 长度帧不冒充 Ethernet II（相关流缺失）',
    () => analyze(req(pcap([lengthFrame, ...frames.slice(1)]))), 'NO_SYN');
  // 噪声帧不影响结论
  const withNoise = pcap([arpFrame(), arpFrame(), ...frames]);
  eq('link: ARP 噪声被忽略', analyze(req(withNoise)).commands.map((c) => c.text), ['PING']);
  // IP 头校验和错误
  const bad = s.data(0, 6, { badChecksum: true });
  expectCode('ipv4: 头校验和错误立即作废',
    () => analyze(req(pcap([s.syn(), bad, s.fin(6)]))), 'IP_CHECKSUM');
}

// ---------- 4. IP 分片 ----------
{
  const s = makeSession({ commands: ['NAV FIX A1', 'HOLD'] }); // 帧长 12+6 = 18 字节
  const seg = tcp({ sport: s.sport, dport: s.dport, seq: s.dataStart, flags: 0x18, data: s.stream });
  const frags = fragmentPayload({ srcIp: s.srcIp, dstIp: s.dstIp, id: 0x9000, payload: seg, chunkSize: 8 });
  eq('分片: 38 字节 IP 载荷（20 TCP 头 + 18 数据）切成 5 片', frags.length, 5);
  // 到达顺序：f1 f3 f0 f4 f2；包号 SYN=#1，碎片=#2..#6，FIN=#7
  const shuffled = [frags[1], frags[3], frags[0], frags[4], frags[2]];
  const r = analyze(req(pcap([s.syn(), ...shuffled, s.fin(18)])));
  eq('分片: 乱序到达仍正确重建', r.commands.map((c) => c.text), ['NAV FIX A1', 'HOLD']);
  // 流[0..7] 在 frag2(=#6)，流[8..11] 在 frag3(=#3)；流[12..17] 在 frag4(=#5)
  eq('分片: 指令一映射到承载它的碎片包号', r.commands[0].packets, [3, 6]);
  eq('分片: 指令二映射到末片包号', r.commands[1].packets, [5]);

  // 缺末片
  expectCode('分片: 缺末片拒绝',
    () => analyze(req(pcap([s.syn(), ...frags.slice(0, 4)]))), 'MISSING_FRAGMENT');
  // 缺中间片（保留末片）
  expectCode('分片: 中间空洞拒绝',
    () => analyze(req(pcap([s.syn(), ...frags.filter((_, i) => i !== 2)]))), 'MISSING_FRAGMENT');
  // 同偏移分片字节冲突（用 ipFragment 重建，确保 IP 头校验和仍然正确）
  const evilPart = Buffer.from(seg.subarray(16, 24)); // 第 3 片 IP 载荷（offset=2），含流[4..11]
  evilPart[2] ^= 0x5a;
  const evil = ipFragment({ srcIp: s.srcIp, dstIp: s.dstIp, id: 0x9000, part: evilPart, offset: 2, mf: true });
  expectCode('分片: 同偏移异字节拒绝拼接',
    () => analyze(req(pcap([s.syn(), ...frags, evil, s.fin(18)]))), 'FRAGMENT_CONFLICT');
}

// ---------- 4d. 断续链路四类捕获：首片后到 / 顺序复用相同标识 / 迟到相同重传 / 异字节覆盖 ----------
{
  // ① 首片后到：一个承载数据的数据报被分片，末片+中间片先到、偏移 0 的首片最晚到
  {
    const s = makeSession({ commands: ['ARM GRID-07', 'SAFE'] }); // 帧长 13+6 = 19
    const seg = tcp({ sport: s.sport, dport: s.dport, seq: s.dataStart, flags: 0x18, data: s.stream });
    const f = fragmentPayload({ srcIp: s.srcIp, dstIp: s.dstIp, id: 0x6100, payload: seg, chunkSize: 8 });
    // 到达：末片 f4(#2)、f2(#3)/f3(#4)/f1(#5)，首片 f0(#6) 最后；SYN(#1) FIN(#7)
    const cap = pcap([s.syn(), f[4], f[2], f[3], f[1], f[0], s.fin(19)]);
    let r = null;
    try { r = analyze(req(cap)); } catch (e) { ok('①首片后到: 完整乱序分片应重组', false, e.message); }
    if (r) {
      eq('①首片后到: 重建指令连续', r.commands.map((c) => c.text), ['ARM GRID-07', 'SAFE']);
      eq('①首片后到: SYN/FIN 包号', [r.synPacket, r.finPacket], [1, 7]);
      // seg=20 头+19 数据，8 字节切片：f2(#3)→流[0,4)，f3(#4)→流[4,12)，末片 f4(#2)→流[12,19)
      eq('①首片后到: 指令一包号归属(跨3片)', r.commands[0].packets, [2, 3, 4]);
      eq('①首片后到: 指令二包号归属(最先到达的末片)', r.commands[1].packets, [2]);
      eq('①首片后到: 指令区间', [r.commands[0].byteRange, r.commands[1].byteRange], [[0, 13], [13, 19]]);
    }
  }

  // ② 顺序复用相同标识：两个各自分片、长度/内容不同的数据报先后复用同一 IP id
  //    gen2 仍“末片先到、首片后到”，必须独立重组，绝不与 gen1 历史字节拼接
  {
    const s = makeSession({ commands: ['REUSE-ONE', 'TWO'] }); // 帧长 11+5 = 16
    const seg1 = tcp({ sport: s.sport, dport: s.dport, seq: s.dataStart, flags: 0x18, data: s.stream.subarray(0, 11) });
    const seg2 = tcp({ sport: s.sport, dport: s.dport, seq: (s.dataStart + 11) >>> 0, flags: 0x18, data: s.stream.subarray(11, 16) });
    const g1 = fragmentPayload({ srcIp: s.srcIp, dstIp: s.dstIp, id: 0x7777, payload: seg1, chunkSize: 8 }); // 封口 31
    const g2 = fragmentPayload({ srcIp: s.srcIp, dstIp: s.dstIp, id: 0x7777, payload: seg2, chunkSize: 8 }); // 封口 25
    // gen1 #2..#5 收齐结束；gen2 末片#6→中间#7/#8→首片#9；FIN #10
    const cap = pcap([s.syn(), ...g1, g2[3], g2[2], g2[1], g2[0], s.fin(16)]);
    let r = null;
    try { r = analyze(req(cap)); } catch (e) { ok('②顺序复用: 两个数据报应独立重组', false, e.message); }
    if (r) {
      eq('②顺序复用: 指令不串代际', r.commands.map((c) => c.text), ['REUSE-ONE', 'TWO']);
      eq('②顺序复用: 流长度', r.streamLength, 16);
      eq('②顺序复用: 重组数据报数(SYN/FIN+2分片报)', r.datagramCount, 4);
      // 流[0,4) 在 g1[2](#4)，流[4,11) 在末片 g1[3](#5)
      eq('②顺序复用: 指令一仅属第一代包号', r.commands[0].packets, [4, 5]);
      // 流[11,15) 在 g2[2](#7)，流[15] 在最先到达的末片 g2[3](#6)；与第一代不交叉
      eq('②顺序复用: 指令二仅属第二代包号', r.commands[1].packets, [6, 7]);
      ok('②顺序复用: 两代包号不交叉',
        !r.commands[0].packets.some((p) => r.commands[1].packets.includes(p)));
    }
  }

  // ②' 分片数据报与“已完整结束（未分片）”数据报复用同一 IPv4 标识，两个方向都要独立
  {
    const s = makeSession({ commands: ['PING', 'PONG'] }); // 6+6 = 12

    // 分片数据报（流[0,6)，全部中间片+末片先到、首片最后到）结束后，再来一条未分片完整数据报复用同 id（流[6,12)）
    {
      const frags = s.dataFrags(0, 6, 8, 0xaaaa); // 26 字节 IP 载荷 → 4 片
      const unfrag = s.data(6, 6, { id: 0xaaaa });
      const order = [frags[3], frags[1], frags[2], frags[0]]; // 末片#2、中间#3/#4、首片#5 最后
      let r = null;
      try { r = analyze(req(pcap([s.syn(), ...order, unfrag, s.fin(12)]))); }
      catch (e) { ok('②′分片→完整复用: 应独立重组', false, e.message); }
      if (r) {
        eq('②′分片→完整复用: 指令', r.commands.map((c) => c.text), ['PING', 'PONG']);
        // 流[0,4) 在 f2#4，流[4,6) 在最先到达的末片 f3#2；首片 f0#5 只含 TCP 头
        eq('②′分片→完整复用: 指令一包号(末片先到/首片最后)', r.commands[0].packets, [2, 4]);
        eq('②′分片→完整复用: 指令二仅属完整数据报#6', r.commands[1].packets, [6]);
      }
    }

    // 反向：先一条未分片完整数据报（流[0,6)），其后分片数据报（流[6,12)，首片最后到）复用同 id
    {
      const unfrag = s.data(0, 6, { id: 0xbbbb });
      const frags = s.dataFrags(6, 6, 8, 0xbbbb);
      const order = [frags[3], frags[1], frags[2], frags[0]]; // 末片#3、中间#4/#5、首片#6 最后
      let r = null;
      try { r = analyze(req(pcap([s.syn(), unfrag, ...order, s.fin(12)]))); }
      catch (e) { ok('②′完整→分片复用: 应独立重组', false, e.message); }
      if (r) {
        eq('②′完整→分片复用: 指令', r.commands.map((c) => c.text), ['PING', 'PONG']);
        eq('②′完整→分片复用: 指令一仅属完整数据报#2', r.commands[0].packets, [2]);
        eq('②′完整→分片复用: 指令二包号(末片#3/中间#5,首片#6仅头)', r.commands[1].packets, [3, 5]);
      }
    }
  }

  // ③ 迟到的完全相同重传：数据报结束后又来逐字节相同的中间片与首片，接受并计入包号
  {
    const s = makeSession({ commands: ['LATE-RETX', 'OK'] }); // 帧长 11+4 = 15
    const seg = tcp({ sport: s.sport, dport: s.dport, seq: s.dataStart, flags: 0x18, data: s.stream });
    const f = fragmentPayload({ srcIp: s.srcIp, dstIp: s.dstIp, id: 0x8200, payload: seg, chunkSize: 8 });
    const dupMid = ipFragment({ srcIp: s.srcIp, dstIp: s.dstIp, id: 0x8200, part: seg.subarray(24, 32), offset: 3, mf: true });   // #8 同 f3
    const dupFirst = ipFragment({ srcIp: s.srcIp, dstIp: s.dstIp, id: 0x8200, part: seg.subarray(0, 8), offset: 0, mf: true });    // #9 同 f0 首片
    const cap = pcap([s.syn(), ...f, s.fin(15), dupMid, dupFirst]); // 正常 #2..#6，FIN #7
    let r = null;
    try { r = analyze(req(cap)); } catch (e) { ok('③迟到相同重传: 应接受', false, e.message); }
    if (r) {
      eq('③迟到相同重传: 重建指令', r.commands.map((c) => c.text), ['LATE-RETX', 'OK']);
      // 流[0,12) 由 #4(流0..3)/#5(流4..11) 承载，#8 是 #5 相同字节的迟到重传，也要计入
      eq('③迟到相同重传: 指令一含迟到重传包号', r.commands[0].packets, [4, 5, 8]);
      eq('③迟到相同重传: 指令二包号(含跨片重传)', r.commands[1].packets, [5, 6, 8]);
      ok('③迟到相同重传: 纯首片重传(#9,仅IP头)不计入任何指令',
        !r.commands.some((c) => c.packets.includes(9)));
    }
  }

  // ④ 不同字节覆盖：代际内（封口前）与代际间（结束后且无新首片）都必须 FRAGMENT_CONFLICT 定位
  {
    const s = makeSession({ commands: ['NAV FIX A1', 'HOLD'] }); // 18
    const seg = tcp({ sport: s.sport, dport: s.dport, seq: s.dataStart, flags: 0x18, data: s.stream });

    // ④-a 代际内：f2(#4) 已安放 offset=2，封口末片到达前 #5 以异字节覆盖同偏移
    const f = fragmentPayload({ srcIp: s.srcIp, dstIp: s.dstIp, id: 0x9300, payload: seg, chunkSize: 8 });
    const inner = Buffer.from(seg.subarray(16, 24)); inner[4] ^= 0xa5; // IP 偏移 20 处改字节
    const evilInner = ipFragment({ srcIp: s.srcIp, dstIp: s.dstIp, id: 0x9300, part: inner, offset: 2, mf: true });
    try {
      analyze(req(pcap([s.syn(), f[0], f[1], f[2], evilInner, f[3], f[4], s.fin(18)])));
      ok('④-a代际内覆盖: 必须拒绝', false);
    } catch (e) {
      ok('④-a代际内覆盖: FRAGMENT_CONFLICT', e.code === 'FRAGMENT_CONFLICT', e.code);
      eq('④-a代际内覆盖: 冲突两包号', [e.packet, e.packet2], [4, 5]);
      eq('④-a代际内覆盖: 数据报内偏移', e.offset, 20);
      eq('④-a代际内覆盖: 冲突区间', e.range, [20, 21]);
    }

    // ④-b 代际间：数据报 #2..#6 已结束、FIN #7，#8 以异字节覆盖历史偏移且再无新首片
    const g = fragmentPayload({ srcIp: s.srcIp, dstIp: s.dstIp, id: 0x9400, payload: seg, chunkSize: 8 });
    const cross = Buffer.from(seg.subarray(24, 32)); cross[0] ^= 0x5a; // IP 偏移 24 处改字节
    const evilCross = ipFragment({ srcIp: s.srcIp, dstIp: s.dstIp, id: 0x9400, part: cross, offset: 3, mf: true });
    try {
      analyze(req(pcap([s.syn(), ...g, s.fin(18), evilCross])));
      ok('④-b代际间覆盖: 必须拒绝', false);
    } catch (e) {
      ok('④-b代际间覆盖: FRAGMENT_CONFLICT（不得伪装成新数据报缺片）', e.code === 'FRAGMENT_CONFLICT', e.code);
      // IP 偏移 24 的原字节由 #5(f3) 承载，覆盖者 #8；保留首个原始包号/偏移/冲突区间
      eq('④-b代际间覆盖: 历史包/覆盖包', [e.packet, e.packet2], [5, 8]);
      eq('④-b代际间覆盖: 数据报内偏移', e.offset, 24);
      eq('④-b代际间覆盖: 冲突区间', e.range, [24, 25]);
      ok('④-b代际间覆盖: 给出已到分片包号',
        Array.isArray(e.extra?.fragmentPackets) && e.extra.fragmentPackets.includes(8));
    }
  }

  // ⑤ 截断：分片越过末片封口长度（代际内）或迟到片越过已结束数据报封口（代际间），均拒绝
  {
    const s = makeSession({ commands: ['TRUNC-CHK'] });
    const seg = tcp({ sport: s.sport, dport: s.dport, seq: s.dataStart, flags: 0x18, data: s.stream }); // 20+11 = 31

    // ⑤-a 代际内：末片封口 31，另一片 offset=3 覆盖到 32（末片先到）
    {
      const last = ipFragment({ srcIp: s.srcIp, dstIp: s.dstIp, id: 0x9500, part: seg.subarray(24, 31), offset: 3, mf: false }); // 封口 31
      const over = ipFragment({ srcIp: s.srcIp, dstIp: s.dstIp, id: 0x9500, part: seg.subarray(16, 24), offset: 3, mf: true });  // [24,32) 越过封口
      const f0 = ipFragment({ srcIp: s.srcIp, dstIp: s.dstIp, id: 0x9500, part: seg.subarray(0, 8), offset: 0, mf: true });
      try {
        analyze(req(pcap([s.syn(), last, over, f0]))); // 末片 #2、越界片 #3、首片 #4
        ok('⑤-a代际内截断: 必须拒绝', false);
      } catch (e) {
        ok('⑤-a代际内截断: FRAGMENT_CONFLICT', e.code === 'FRAGMENT_CONFLICT', e.code);
        eq('⑤-a代际内截断: 包号', [e.packet, e.packet2], [2, 3]);
        eq('⑤-a代际内截断: 封口偏移/越界区间', [e.offset, e.range], [31, [31, 32]]);
      }
    }

    // ⑤-b 代际间：gen1(#2..#5) 封口 31 并完整结束；#6 前 7 字节与历史相同、却多 1 字节越过封口
    {
      const f = fragmentPayload({ srcIp: s.srcIp, dstIp: s.dstIp, id: 0x9600, payload: seg, chunkSize: 8 });
      const overPart = Buffer.concat([seg.subarray(24, 31), Buffer.from([0x5a])]); // 8 字节 @offset3 → [24,32)
      const over = ipFragment({ srcIp: s.srcIp, dstIp: s.dstIp, id: 0x9600, part: overPart, offset: 3, mf: true });
      try {
        analyze(req(pcap([s.syn(), ...f, s.fin(11), over])));
        ok('⑤-b代际间截断: 必须拒绝', false);
      } catch (e) {
        ok('⑤-b代际间截断: FRAGMENT_CONFLICT（不得并入历史、不得另开缺片代际）', e.code === 'FRAGMENT_CONFLICT', e.code);
        eq('⑤-b代际间截断: 封口偏移/越界区间', [e.offset, e.range], [31, [31, 32]]);
      }
    }
  }
}


// ---------- 4b. VLAN / IP-TCP 选项 / 以太网填充 ----------
{
  const s = makeSession({ commands: ['VL','OPTS','PAD'] }); // 帧长 4+6+5 = 15
  // 802.1Q 包裹
  const vlan = (frame) => eth(
    Buffer.concat([Buffer.from([0x00, 0x00, 0x08, 0x00]), frame.subarray(14)]), 0x8100);
  // 以太网最小帧 60 字节填充（IP totalLen 不变，填充必须被忽略）
  const pad60 = (frame) => Buffer.concat([frame, Buffer.alloc(Math.max(0, 60 - frame.length))]);
  const cap1 = pcap([pad60(vlan(s.syn())), pad60(vlan(s.data(0, 8))), s.data(8, 7), s.fin(15)]);
  eq('封装: 802.1Q 标签 + 以太网填充下仍正确重建',
    analyze(req(cap1)).commands.map((c) => c.text), ['VL', 'OPTS', 'PAD']);

  // 带 IP 选项（IHL=6）与 TCP 选项（data offset=6）的 SYN 与数据包
  const ipOptPkt = (srcIp, dstIp, tcpSeg) => {
    const opts = Buffer.from([0x01, 0x01, 0x01, 0x00]); // NOP NOP NOP EOL
    const head = Buffer.alloc(24);
    head[0] = 0x46; // version 4, IHL 6
    head.writeUInt16BE(24 + tcpSeg.length, 2);
    head.writeUInt16BE(0x7777, 4);
    head.writeUInt16BE(0x4000, 6); // DF
    head[8] = 64; head[9] = 6;
    srcIp.copy(head, 12); dstIp.copy(head, 16);
    opts.copy(head, 20);
    head.writeUInt16BE(computeIpChecksum(head), 10);
    return eth(Buffer.concat([head, tcpSeg]));
  };
  const synOpts = Buffer.alloc(24);
  synOpts.writeUInt16BE(s.sport, 0); synOpts.writeUInt16BE(s.dport, 2);
  synOpts.writeUInt32BE(s.isn >>> 0, 4);
  synOpts[12] = 0x60; // data offset 6
  synOpts[13] = 0x02; // SYN
  synOpts.writeUInt16BE(8192, 14);
  synOpts[20] = 0x02; synOpts[21] = 0x04; synOpts.writeUInt16BE(1460, 22); // MSS
  const dataSeg = Buffer.concat([
    (() => { const h = Buffer.alloc(20);
      h.writeUInt16BE(s.sport, 0); h.writeUInt16BE(s.dport, 2);
      h.writeUInt32BE(s.dataStart, 4); h[12] = 0x50; h[13] = 0x18;
      h.writeUInt16BE(8192, 14); return h; })(),
    s.stream,
  ]);
  const finSeg = tcp({ sport: s.sport, dport: s.dport, seq: (s.dataStart + 15) >>> 0, flags: 0x11 });
  const cap2 = pcap([
    ipOptPkt(s.srcIp, s.dstIp, synOpts),
    ipOptPkt(s.srcIp, s.dstIp, dataSeg),
    ipOptPkt(s.srcIp, s.dstIp, finSeg),
  ]);
  eq('封装: 带 IP 选项与 TCP MSS 选项仍正确解析',
    analyze(req(cap2)).commands.map((c) => c.text), ['VL', 'OPTS', 'PAD']);
}

// ---------- 4c. SYN 序号冲突 ----------
{
  const s = makeSession({ commands: ['X'] });
  const syn2 = ipv4Packet({
    srcIp: s.srcIp, dstIp: s.dstIp, id: 9999,
    part: tcp({ sport: s.sport, dport: s.dport, seq: (s.isn + 100) >>> 0, flags: 0x02 }),
  });
  expectCode('tcp: 两个 SYN 序号不同即拒绝',
    () => analyze(req(pcap([s.syn(), syn2, s.data(0, 3), s.fin(3)]))), 'CONFLICT');
}

// ---------- 5. TCP 重组 ----------
{
  const s = makeSession({ commands: ['AAA', 'BBBB', 'CCCCC'] }); // 5+6+7 = 18 字节
  const L = s.stream.length;
  eq('tcp: 样例流长度', L, 18);

  // 乱序
  const ooo = [s.syn(), s.data(12, 6), s.data(6, 6), s.data(0, 6), s.fin(L)];
  eq('tcp: 乱序段按序重建', analyze(req(pcap(ooo))).commands.map((c) => c.text),
    ['AAA', 'BBBB', 'CCCCC']);

  // 同字节重传（完全重叠、部分重叠）
  const retx = [s.syn(), s.data(0, 9), s.data(6, 9), s.data(0, 12), s.data(12, 6), s.fin(L)];
  eq('tcp: 字节相同的重传接受', analyze(req(pcap(retx))).streamLength, L);

  // 异字节重传 → CONFLICT，定位首个包号/偏移/区间
  const bad = Buffer.from(s.stream.subarray(6, 12));
  bad[1] = 0x41 ^ 0xff;
  const cap = pcap([s.syn(), s.data(0, 9), s.data(6, 6, { data: bad }), s.fin(L)]);
  try {
    analyze(req(cap));
    ok('tcp: 异字节重叠拒绝', false);
  } catch (e) {
    ok('tcp: 异字节重叠拒绝', e.code === 'CONFLICT', e.message);
    eq('tcp: 冲突定位首个包号', [e.packet, e.packet2], [2, 3]);
    eq('tcp: 冲突定位流内偏移', e.offset, 7);
    ok('tcp: 给出冲突半开区间', Array.isArray(e.range) && e.range[0] === 7 && e.range[1] >= 8,
      JSON.stringify(e.range));
  }

  // 流内空洞
  expectCode('tcp: FIN 前存在空洞拒绝',
    () => analyze(req(pcap([s.syn(), s.data(0, 6), s.data(12, 6), s.fin(L)]))), 'STREAM_HOLE');

  // 缺 SYN / 缺 FIN
  expectCode('tcp: 缺失起始 SYN 拒绝',
    () => analyze(req(pcap([s.data(0, 9), s.data(9, 9), s.fin(L)]))), 'NO_SYN');
  expectCode('tcp: 缺失 FIN 拒绝',
    () => analyze(req(pcap([s.syn(), s.data(0, 6), s.data(6, 6), s.data(12, 6)]))), 'NO_FIN');

  // 32 位回绕：ISN=0xFFFFFFFE，数据起始 0xFFFFFFFF，首字节即回绕
  const w = makeSession({ isn: 0xfffffffe, commands: ['WRAP TEST'] }); // 11 字节
  const wFrames = [
    w.syn(),
    w.data(0, 4),   // seq FFFFFFFF,00,01,02
    w.data(4, 7),   // seq 03..
    w.fin(11),
  ];
  const wr = analyze(req(pcap(wFrames)));
  eq('tcp: 跨 0xFFFFFFFF 回绕重建', wr.commands.map((c) => c.text), ['WRAP TEST']);
  eq('tcp: ISN 如实报告', wr.isn, 0xfffffffe);

  // SYN 重传（相同 ISN）必须接受
  const synRetx = [s.syn(), s.syn(), s.data(0, L), s.fin(L)];
  eq('tcp: 相同 SYN 重传接受', analyze(req(pcap(synRetx))).streamLength, L);
}

// ---------- 6. 指令格式 ----------
{
  // 尾随残字节（1 字节）
  const one = commandFrame('GO');
  const trailing = Buffer.concat([sessPcap([one, Buffer.from([0x07])])]);
  expectCode('指令: 尾随单残字节拒绝', () => analyze(req(trailing)), 'TRAILING_BYTES');

  // 长度声称超过 FIN 前流
  function sessPcap(parts) {
    const body = Buffer.concat(parts);
    const s2 = makeSession({ sport: 5100, dport: 8080 });
    return pcap([
      ipv4Packet({ srcIp: s2.srcIp, dstIp: s2.dstIp, part: tcp({ sport: 5100, dport: 8080, seq: s2.isn, flags: 0x02 }) }),
      ipv4Packet({ srcIp: s2.srcIp, dstIp: s2.dstIp, part: tcp({ sport: 5100, dport: 8080, seq: (s2.isn + 1) >>> 0, flags: 0x18, data: body }) }),
      ipv4Packet({ srcIp: s2.srcIp, dstIp: s2.dstIp, part: tcp({ sport: 5100, dport: 8080, seq: (s2.isn + 1 + body.length) >>> 0, flags: 0x11 }) }),
    ]);
  }
  const declTooBig = Buffer.concat([Buffer.from([0x00, 0x10]), Buffer.from('short')]);
  expectCode('指令: 长度前缀超出流尾拒绝', () => analyze(req(sessPcap([declTooBig]))), 'TRUNCATED_COMMAND');

  // 非 ASCII 载荷
  const nonAscii = Buffer.concat([Buffer.from([0x00, 0x03]), Buffer.from([0x41, 0x00, 0x42])]);
  expectCode('指令: 非可见 ASCII 拒绝', () => analyze(req(sessPcap([nonAscii]))), 'NON_ASCII');

  // 长度前缀 0
  expectCode('指令: 零长度指令拒绝', () => analyze(req(sessPcap([Buffer.from([0x00, 0x00, 0x41])]))), 'INVALID_COMMAND');
}

// ---------- 7. 五元组 / 上限 ----------
{
  const s = makeSession({ commands: ['Q'] });
  const cap = pcap([s.syn(), s.data(0, 3), s.fin(3)]);
  expectCode('tuple: 源地址不匹配拒绝', () => analyze(req(cap, { srcIp: '10.9.9.9' })), 'NO_MATCH');
  expectCode('tuple: 端口不匹配拒绝', () => analyze(req(cap, { srcPort: 5101 })), 'NO_MATCH');
  expectCode('tuple: 非法 IPv4 拒绝', () => analyze(req(cap, { srcIp: '10.0.0.256' })), 'BAD_TUPLE');
  const big = 'A'.repeat(256 * 1024 + 1);
  expectCode('输入: 超过 256 KiB 拒绝', () => analyze({ ...T, pcapBase64: big }), 'TOO_LARGE');
}

// ---------- 8. 抓包截断（snaplen） / linktype / 空流 ----------
{
  const s = makeSession({ commands: ['TRUNCATED-CAPTURE-CHECK'] });
  const full = s.data(0, s.stream.length);
  const cut = Buffer.from(full.subarray(0, 14 + 20 + 10)); // 连 TCP 头都切残
  expectCode('捕获: origLen>incl 的截断包拒绝',
    () => analyze(req(pcap([s.syn(), cut, s.fin(s.stream.length)], { origLens: [full.length, full.length, null].map((v) => v ?? undefined) }))),
    'TRUNCATED_CAPTURE');

  // 非 Ethernet II 链路层（如 raw IP linktype=101）拒绝
  const rawIp = full.subarray(14);
  expectCode('捕获: 非 Ethernet linktype 拒绝',
    () => analyze(req(pcap([rawIp], { linktype: 101 }))), 'UNSUPPORTED_LINKTYPE');

  // SYN 与 FIN 之间无数据字节 → EMPTY_STREAM
  expectCode('tcp: SYN→FIN 空流拒绝',
    () => analyze(req(pcap([s.syn(), s.fin(0)]))), 'EMPTY_STREAM');

  // 分片组中某一片 IPv4 头校验和错误：必须先按校验和作废
  const seg2 = tcp({ sport: s.sport, dport: s.dport, seq: s.dataStart, flags: 0x18, data: s.stream });
  const frags2 = fragmentPayload({ srcIp: s.srcIp, dstIp: s.dstIp, id: 0x5500, payload: seg2, chunkSize: 8 });
  const badFrag = ipFragment({
    srcIp: s.srcIp, dstIp: s.dstIp, id: 0x5500,
    part: seg2.subarray(0, 8), offset: 0, mf: true, badChecksum: true,
  });
  expectCode('ipv4: 分片头校验和错误同样作废',
    () => analyze(req(pcap([s.syn(), badFrag, ...frags2.slice(1)]))), 'IP_CHECKSUM');
}

// ---------- 9. 成功结论结构与包号/区间映射 ----------
{
  const s = makeSession({ isn: 0x100, commands: ['CMD-ONE', 'CMD-TWO!'] }); // 帧长 9+10 = 19
  const cap = pcap([
    arpFrame(),                 // #1 噪声
    s.syn(),                    // #2
    s.data(0, 11),              // #3 流 [0,11)：覆盖指令一全部 + 指令二前 2 字节
    s.data(9, 10),              // #4 重叠重传 [9,11) 并补全 [11,19)
    s.fin(19),                  // #5
  ]);
  const r = analyze(req(cap));
  eq('结构: 指令数', r.commands.length, 2);
  eq('结构: 指令文本', r.commands.map((c) => c.text), ['CMD-ONE', 'CMD-TWO!']);
  eq('结构: SYN 包号', r.synPacket, 2);
  eq('结构: FIN 包号', r.finPacket, 5);
  eq('结构: 第一条区间', r.commands[0].byteRange, [0, 9]);
  eq('结构: 第二条区间', r.commands[1].byteRange, [9, 19]);
  eq('结构: 第二条载荷区间', r.commands[1].payloadRange, [11, 19]);
  eq('结构: 两条指令的承载包号集合',
    [...new Set(r.commands.flatMap((c) => c.packets))].sort((a, b) => a - b), [3, 4]);
  eq('结构: 流长度', r.streamLength, 19);
}

// ---------- 10. 页面构建 ----------
{
  const htmlPath = path.join(ROOT, 'public', 'index.html');
  const html = await readFile(htmlPath, 'utf8');
  const refs = [...html.matchAll(/(?:src|href)="(\/[^"]+)"/g)].map((m) => m[1]);
  ok('页面: 存在资源引用', refs.length >= 2, refs.join(','));
  for (const r of refs) {
    // eslint-disable-next-line no-await-in-loop
    await access(path.join(ROOT, 'public', r)).then(
      () => ok(`页面: 资源存在 ${r}`, true),
      () => ok(`页面: 资源存在 ${r}`, false),
    );
  }
  // 页面与同构库必须是语法合法的 ESM（node --check）
  for (const f of ['public/app.js', 'lib/analyze.js', 'lib/tcp.js', 'lib/ipdefrag.js',
    'lib/decode.js', 'lib/commands.js', 'lib/base64.js', 'src/server.js']) {
    try {
      execFileSync(process.execPath, ['--check', path.join(ROOT, f)], { stdio: 'pipe' });
      ok(`页面: ESM 语法检查 ${f}`, true);
    } catch (e) {
      ok(`页面: ESM 语法检查 ${f}`, false, String(e.stderr || e));
    }
  }
  // 关键交互元素齐备
  for (const id of ['srcIp', 'srcPort', 'dstIp', 'dstPort', 'pcap', 'btn-verify', 'btn-clear',
    'btn-sample-good', 'btn-sample-conflict', 'result']) {
    ok(`页面: 控件 #${id}`, html.includes(`id="${id}"`));
  }
}

// ---------- 11. HTTP 冒烟 ----------
{
  // 容器编排模式：APP_URL 指向已就绪的 app 服务；本地模式：自行拉起一个临时实例
  const externalUrl = process.env.APP_URL ? process.env.APP_URL.replace(/\/$/, '') : null;
  const port = String(41000 + Math.floor(Math.random() * 4000));
  const child = externalUrl ? null : spawn(process.execPath, [path.join(ROOT, 'src', 'server.js')], {
    env: { ...process.env, PORT: port },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const base = externalUrl ?? `http://127.0.0.1:${port}`;
  let logs = '';
  if (child) {
    child.stdout.on('data', (d) => { logs += d; });
    child.stderr.on('data', (d) => { logs += d; });
  }

  async function waitReady(deadline = Date.now() + 15000) {
    while (Date.now() < deadline) {
      try {
        const res = await fetch(`${base}/healthz`);
        if (res.ok) return;
      } catch { /* 未就绪，重试 */ }
      await new Promise((r) => setTimeout(r, externalUrl ? 300 : 100));
    }
    throw new Error(`server at ${base} never became ready`);
  }

  let smokeOk = 0;
  try {
    await waitReady();
    const h = await fetch(`${base}/healthz`);
    ok('冒烟: GET /healthz 200', h.status === 200, String(h.status));
    const hj = await h.json();
    ok('冒烟: /healthz JSON status=ok', hj.status === 'ok', JSON.stringify(hj));

    const home = await fetch(`${base}/`);
    const homeText = await home.text();
    ok('冒烟: 首页 200 且为页面', home.status === 200 && homeText.includes('发起复核'));

    const appjs = await fetch(`${base}/app.js`);
    ok('冒烟: app.js 200', appjs.status === 200);
    const lib = await fetch(`${base}/lib/analyze.js`);
    ok('冒烟: 同构库经静态服务可达', lib.status === 200);

    // 本题样例经 HTTP 拉取并端到端复核
    const manifest = JSON.parse(await (await fetch(`${base}/samples/manifest.json`)).text());
    for (const kind of ['good', 'conflict']) {
      const spec = manifest[kind];
      const b64Text = (await (await fetch(`${base}/samples/${spec.file}`)).text()).replace(/\s/g, '');
      const input = { ...manifest.tuple, pcapBase64: b64Text };
      if (kind === 'good') {
        const r = analyze(input);
        smokeOk += r.commands.length === spec.commands.length
          && r.commands.every((c, i) => c.text === spec.commands[i].text)
          && r.synPacket === spec.synPacket && r.finPacket === spec.finPacket
          && r.streamLength === spec.streamLength && r.packetCount === spec.packetCount;
        ok('冒烟: good 样例指令/包号/长度全部符合', smokeOk === 1,
          JSON.stringify(r.commands.map((c) => c.text)));
      } else {
        try {
          analyze(input);
          ok('冒烟: conflict 样例必须拒绝', false);
        } catch (e) {
          ok('冒烟: conflict 样例 CONFLICT 定位符合',
            e.code === spec.code && e.packet === spec.packet && e.packet2 === spec.packet2
            && e.offset === spec.offset && JSON.stringify(e.range) === JSON.stringify(spec.range),
            `${e.code} ${e.packet}/${e.packet2}@${e.offset}`);
        }
      }
    }
  } catch (e) {
    ok('冒烟: 服务拉起与请求', false, `${e.message}\n${logs}`);
  } finally {
    if (child) {
      child.kill('SIGTERM');
      await new Promise((r) => setTimeout(r, 150));
      if (child.exitCode === null) child.kill('SIGKILL');
    }
  }
}

// ---------- 汇总：一次运行后以退出码结束 ----------
console.log(`\nverify: ${passed} passed, ${failed} failed`);
if (failed) {
  for (const f of failures) console.error(`  ✗ ${f}`);
  process.exit(1);
}
console.log('verify: ALL CHECKS PASSED');
process.exit(0);
