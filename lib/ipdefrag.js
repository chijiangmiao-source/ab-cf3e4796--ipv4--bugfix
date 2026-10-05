import { fail } from './errors.js';

// IPv4 分片重组：键 = (源, 目的, 协议, 标识)。
// 断续链路上同一标识在先前数据报结束后会被复用，因此每个键维护一个“代”序列：
//  - 当前代未闭合（末片未到或存在空洞）时，任何偏移的分片都归入当前代，
//    完整但任意乱序的分片（末片/中间片先到、首片后到）都能重组成原数据报；
//  - 当前代一旦闭合（末片到齐且 [0, 总长) 无空洞），之后到达的同标识分片
//    一律开启新一代独立重组，绝不与历史字节拼接；
//  - 收尾时，若最末一代始终未闭合，且其全部分片都是上一代已闭合数据报的
//    完全相同重传，则并入上一代——迟到的完全相同重传仍作为同一数据报的依据；
//  - 其余无法一致解释的情形（同偏移/跨代覆盖字节不同、缺末片、中间空洞）
//    一律拒绝：FRAGMENT_CONFLICT / MISSING_FRAGMENT，并保留首个原始包号、
//    偏移与冲突区间。
// 每个重组后的数据报保留逐字节来源包号，供指令→原始包号映射。

class FragmentGroup {
  constructor(key, firstPacket, src, dst) {
    this.key = key;
    this.firstPacket = firstPacket;
    this.src = src;
    this.dst = dst;
    this.fragments = []; // {packet, start(字节), end, bytes, mf}，按到达顺序
    this.finalEnd = null; // 末片（MF=0）给出的数据报总长度
    this.lastPacket = null;
    this.assembled = null; // materialize() 缓存：装配字节与逐字节来源包号
    this.assembledOrigin = null;
  }

  // 末片已到且 [0, finalEnd) 被完整覆盖
  isComplete() {
    if (this.finalEnd === null) return false;
    let expect = 0;
    for (const f of sortedFragments(this.fragments)) {
      if (f.start > expect) return false;
      if (f.end > expect) expect = f.end;
    }
    return expect >= this.finalEnd;
  }

  // 装配完整字节序列与逐字节来源包号（同位置先到者优先），结果缓存至下一次变更
  materialize() {
    if (this.assembled) return;
    const data = new Uint8Array(this.finalEnd);
    const origin = new Uint32Array(this.finalEnd);
    for (const f of sortedFragments(this.fragments)) {
      for (let i = f.start; i < f.end && i < this.finalEnd; i++) {
        if (origin[i] === 0) {
          data[i] = f.bytes[i - f.start];
          origin[i] = f.packet;
        }
      }
    }
    this.assembled = data;
    this.assembledOrigin = origin;
  }

  add(ip) {
    this.assembled = null; // 内容变更，作废装配缓存
    this.assembledOrigin = null;
    const start = ip.fragOffset * 8;
    const end = start + ip.payload.length;
    // 同偏移/重叠分片：逐字节比较，任何字节不同即拒绝
    for (const f of this.fragments) {
      const lo = Math.max(start, f.start);
      const hi = Math.min(end, f.end);
      if (lo < hi) {
        for (let i = lo; i < hi; i++) {
          if (ip.payload[i - start] !== f.bytes[i - f.start]) {
            const [p1, p2] = f.packet < ip.num ? [f.packet, ip.num] : [ip.num, f.packet];
            throw fail('FRAGMENT_CONFLICT',
              `分片字节冲突：包 ${p1} 与包 ${p2} 在同一 IP 数据报偏移 ${i} 处字节不同，禁止任选其一拼接`, {
                packet: p1,
                packet2: p2,
                offset: i,
                range: conflictRun(ip.payload, start, f.bytes, f.start, lo, hi),
              });
          }
        }
      }
    }
    this.fragments.push({ packet: ip.num, start, end, bytes: ip.payload, mf: ip.mf });
    if (this.firstPacket > ip.num) this.firstPacket = ip.num;
    if (!ip.mf) {
      if (this.finalEnd !== null && this.finalEnd !== end) {
        throw fail('FRAGMENT_CONFLICT',
          `同一组分片出现两个长度不一致的末片（包 ${this.lastPacket} 与包 ${ip.num}）`, {
            packet: Math.min(this.lastPacket, ip.num),
            packet2: Math.max(this.lastPacket, ip.num),
            offset: Math.min(this.finalEnd, end),
          });
      }
      this.finalEnd = end;
      this.lastPacket = ip.num;
    }
  }

  // 把一代（由迟到重传组成）并入本代：重传分片的包号成为本数据报的依据之一，
  // 逐字节来源仍保持先到者优先，不改写已有归属
  absorb(group) {
    this.fragments.push(...group.fragments);
    this.assembled = null;
    this.assembledOrigin = null;
  }
}

class FragmentGenerations {
  constructor(key) {
    this.key = key;
    this.generations = [];
  }

  add(ip) {
    const current = this.generations[this.generations.length - 1] ?? null;
    if (current !== null && !current.isComplete()) {
      // 当前数据报尚未闭合：无论偏移大小都归入当前代（首片后到、任意乱序）
      current.add(ip);
      return;
    }
    // 没有在进行中的数据报，或先前数据报已完整结束、标识被重新使用：
    // 开启新一代独立重组（若实为迟到的完全相同重传，收尾时会核对并入上一代）
    const g = new FragmentGroup(this.key, ip.num, ip.src, ip.dst);
    this.generations.push(g);
    g.add(ip);
  }

  groups() {
    return this.generations;
  }
}

function sortedFragments(fragments) {
  return [...fragments].sort((a, b) => a.start - b.start || a.packet - b.packet);
}

function conflictRun(aBytes, aOff, bBytes, bOff, lo, hi) {
  let s = lo;
  while (s < hi && aBytes[s - aOff] === bBytes[s - bOff]) s++;
  let e = s;
  while (e < hi && aBytes[e - aOff] !== bBytes[e - bOff]) e++;
  return [s, e];
}

// group 的全部分片是否都是 prev（已闭合数据报）的完全相同重传：
// 范围不越界、逐字节一致；末片（MF=0）分片必须给出一致的总长度
function isPureRetransmissionOf(group, prev) {
  if (!prev.isComplete()) return false;
  prev.materialize();
  for (const f of group.fragments) {
    if (f.end > prev.finalEnd) return false;
    if (!f.mf && f.end !== prev.finalEnd) return false;
    for (let i = f.start; i < f.end; i++) {
      if (f.bytes[i - f.start] !== prev.assembled[i]) return false;
    }
  }
  return true;
}

// 未闭合的一代无法收尾时的拒绝结论：
// 若其分片与上一代已闭合数据报在重叠偏移处字节不同——既不属于上一代（字节冲突），
// 又无法独立闭合（缺片），代际间无法一致解释——按 FRAGMENT_CONFLICT 定位首个分歧；
// 否则按 MISSING_FRAGMENT 报告缺末片/中间空洞。
function incompleteGroupError(g, prev) {
  if (prev && prev.isComplete()) {
    prev.materialize();
    for (const f of g.fragments) { // 按到达顺序定位首个冲突分片
      const hi = Math.min(f.end, prev.finalEnd);
      for (let i = f.start; i < hi; i++) {
        if (f.bytes[i - f.start] !== prev.assembled[i]) {
          let e = i + 1;
          while (e < hi && f.bytes[e - f.start] !== prev.assembled[e]) e++;
          const p1 = prev.assembledOrigin[i];
          return fail('FRAGMENT_CONFLICT',
            `包 ${f.packet} 与已结束的数据报（该字节来自包 ${p1}）在同一标识的数据报偏移 ${i} 处字节不同，且自身所在分片组缺片未闭合，代际间无法一致解释，禁止与历史字节拼接`, {
              packet: p1,
              packet2: f.packet,
              offset: i,
              range: [i, e],
            });
        }
      }
    }
  }
  const frags = sortedFragments(g.fragments);
  // 扫描空洞
  let expect = 0;
  for (const f of frags) {
    if (f.start > expect) break; // 空洞，跳出后统一报告
    if (f.end > expect) expect = f.end;
  }
  const holeEnd = g.finalEnd === null
    ? expect // 末片缺失，空洞起点之后长度未知
    : (() => {
        // 找到空洞后的下一个已到分片起点
        let e = expect;
        for (const f of frags) if (f.start > expect) { e = f.start; break; }
        return e;
      })();
  const next = frags.find((f) => f.start >= expect);
  return fail('MISSING_FRAGMENT',
    g.finalEnd === null
      ? `IP 分片组（首包 ${g.firstPacket}）缺少末片：偏移 ${expect} 起的数据未捕获，不得用残片拼流`
      : `IP 分片组（首包 ${g.firstPacket}）在数据报偏移 ${expect} 处缺片，存在空洞`,
    {
      packet: g.firstPacket,
      ...(next ? { packet2: next.packet } : {}),
      offset: expect,
      range: g.finalEnd === null ? null : [expect, holeEnd],
      extra: { fragmentPackets: frags.map((f) => f.packet) },
    });
}

export function reassembleDatagrams(ipPackets) {
  const datagrams = [];
  const generationsByKey = new Map();

  for (const ip of ipPackets) {
    if (!ip.mf && ip.fragOffset === 0) {
      // 未分片数据报自包含：即使标识与某分片组相同，也独立成章
      const origin = new Uint32Array(ip.payload.length).fill(ip.num);
      datagrams.push({
        kind: 'single', firstPacket: ip.num, packets: [ip.num],
        src: ip.src, dst: ip.dst, data: ip.payload, origin,
      });
      continue;
    }
    const key = `${[...ip.src, ...ip.dst, ip.proto, ip.id >>> 8, ip.id & 0xff].join('.')}`;
    let generations = generationsByKey.get(key);
    if (!generations) {
      generations = new FragmentGenerations(key);
      generationsByKey.set(key, generations);
    }
    generations.add(ip);
  }

  for (const generations of generationsByKey.values()) {
    const groups = generations.groups();
    // 迟到的完全相同重传归并：最末一代若未闭合，且其全部分片都是上一代
    // 已闭合数据报的完全相同重传，则并入上一代，不单独成代
    while (groups.length > 1) {
      const last = groups[groups.length - 1];
      const prev = groups[groups.length - 2];
      if (last.isComplete() || !isPureRetransmissionOf(last, prev)) break;
      prev.absorb(last);
      groups.pop();
    }
    // 构造不变式保证除最末一代外均已闭合；最末一代未闭合即拒绝
    const last = groups[groups.length - 1];
    if (!last.isComplete()) {
      throw incompleteGroupError(last, groups.length > 1 ? groups[groups.length - 2] : null);
    }
    for (const g of groups) {
      g.materialize();
      datagrams.push({
        kind: 'fragment',
        firstPacket: g.firstPacket,
        packets: [...new Set(g.fragments.map((f) => f.packet))].sort((a, b) => a - b),
        src: g.src,
        dst: g.dst,
        data: g.assembled,
        origin: g.assembledOrigin,
      });
    }
  }

  datagrams.sort((a, b) => a.firstPacket - b.firstPacket);
  return datagrams;
}
