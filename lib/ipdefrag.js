import { fail } from './errors.js';

// IPv4 分片重组：键 = (源, 目的, 协议, 标识)。
//
// 同一键在一条捕获里可能先后承载多个数据报（IPv4 标识会被复用），用“代际”区分：
//   - 代际边界只由“末片封口 + 完整性”决定，绝不依赖首片（偏移 0）先到；
//     末片/中间片先到、首片最晚到达时，所有分片仍归入同一代际。
//   - 末片（MF=0）给出封口长度 finalEnd；代际在“偏移 0 已到且 [0,finalEnd) 连续”时
//     完整结束（交付并冻结）。
//   - 代际结束后同键再出现分片：
//       * 逐字节落在已结束数据报范围内且完全相同（含偏移 0 首片）→ 迟到的相同重传，
//         并入同一数据报（补充来源包号），仍作为同一数据报的依据；
//       * 无法与已结束数据报一致解释的分片 → 暂存进一个“无首片的新代际”，等待新的
//         首片（偏移 0）到来后把它作为标识复用的独立数据报处理，绝不与历史字节对拍拼接；
//         若捕获结束仍没有新首片，则它相对历史数据报是无法解释的覆盖/截断，按冲突拒绝。
//   - 代际仍开放时：片越过封口、两个长度不同的末片、同偏移重叠字节不同都按冲突拒绝；
//     最终仍缺片/缺末片则 MISSING_FRAGMENT。
//
// 每个重组数据报保留逐字节来源（origin，取最早承载者）与每个分片的承载区间（ranges），
// 供 TCP 层把“全部承载该字节的原始包号”（含完全相同重传）追溯到指令。

class FragmentGroup {
  constructor(key, firstPacket) {
    this.key = key;
    this.firstPacket = firstPacket; // 该代际最小原始包号
    this.fragments = [];            // {packet, start, end, bytes}，按到达顺序
    this.finalEnd = null;           // 末片（MF=0）封口的数据报总长度
    this.lastPacket = null;
    this.sawFirst = false;          // 是否已收到偏移 0 的首片
    this.completed = false;
    this.datagram = null;           // 完整结束后冻结的数据报
  }

  // 该片确认属于本（开放）代际时调用。返回：
  //   'ADDED'  正常安放
  //   'BEYOND' 整片位于封口长度之后（调用方据此把它交给新代际，本代际留待缺片判定）
  add(ip) {
    const start = ip.fragOffset * 8;
    const end = start + ip.payload.length;

    if (this.finalEnd !== null) {
      if (start >= this.finalEnd) return 'BEYOND';
      if (end > this.finalEnd) {
        // 片起点在封口长度内，却越过末片给出的数据报终点：长度不一致/截断
        throw fail('FRAGMENT_CONFLICT',
          `分片越过数据报封口：包 ${ip.num} 覆盖到偏移 ${end}，但末片（包 ${this.lastPacket}）宣告总长度 ${this.finalEnd}，长度无法一致解释`, {
            packet: Math.min(this.firstPacket, ip.num),
            packet2: Math.max(this.lastPacket, ip.num),
            offset: this.finalEnd,
            range: [this.finalEnd, end],
            extra: { fragmentPackets: this.packetList() },
          });
      }
    }

    if (!ip.mf) {
      if (this.finalEnd !== null && end !== this.finalEnd) {
        throw fail('FRAGMENT_CONFLICT',
          `同一组分片出现两个长度不一致的末片（包 ${this.lastPacket} 宣告 ${this.finalEnd}，包 ${ip.num} 宣告 ${end}）`, {
            packet: Math.min(this.lastPacket, ip.num),
            packet2: Math.max(this.lastPacket, ip.num),
            offset: Math.min(this.finalEnd, end),
            range: [Math.min(this.finalEnd, end), Math.max(this.finalEnd, end)],
            extra: { fragmentPackets: this.packetList() },
          });
      }
      // 新学到封口长度：核对先前已到的片没有越过它
      if (this.finalEnd === null) {
        for (const f of this.fragments) {
          if (f.start >= end || f.end > end) {
            throw fail('FRAGMENT_CONFLICT',
              `末片（包 ${ip.num}）宣告总长度 ${end}，但先到的包 ${f.packet} 覆盖到偏移 ${f.end}，分片相对末片被截断或长度矛盾`, {
                packet: Math.min(ip.num, f.packet),
                packet2: Math.max(ip.num, f.packet),
                offset: Math.min(end, f.end),
                range: [end, Math.max(end, f.end)],
                extra: { fragmentPackets: this.packetList() },
              });
          }
        }
        this.finalEnd = end;
        this.lastPacket = ip.num;
      }
    }

    // 同偏移/重叠分片：逐字节比较，任何字节不同即冲突（代际内覆盖）
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
                extra: { fragmentPackets: this.packetList() },
              });
          }
        }
      }
    }

    this.fragments.push({ packet: ip.num, start, end, bytes: ip.payload });
    if (ip.num < this.firstPacket) this.firstPacket = ip.num;
    if (start === 0) this.sawFirst = true;
    this.maybeComplete();
    return 'ADDED';
  }

  // 该片是否是与已结束数据报逐字节一致、且不越界的完全相同重传
  isIdenticalRetransmit(ip) {
    const start = ip.fragOffset * 8;
    const end = start + ip.payload.length;
    if (!this.completed || end > this.finalEnd) return false;
    for (let i = start; i < end; i++) {
      if (ip.payload[i - start] !== this.datagram.data[i]) return false;
    }
    return true;
  }

  // 作为同一数据报的迟到完全相同重传吸收（含偏移 0 首片重传）
  absorbDuplicate(ip) {
    const start = ip.fragOffset * 8;
    const end = start + ip.payload.length;
    this.datagram.packetsSet.add(ip.num);
    this.datagram.ranges.push({ packet: ip.num, lo: start, hi: end });
  }

  packetList() {
    const ids = new Set(this.fragments.map((f) => f.packet));
    if (this.datagram) for (const p of this.datagram.packetsSet) ids.add(p);
    return [...ids].sort((a, b) => a - b);
  }

  coverageEnd() {
    const frags = [...this.fragments].sort((a, b) => a.start - b.start || a.packet - b.packet);
    let expect = 0;
    for (const f of frags) {
      if (f.start > expect) break; // 空洞
      if (f.end > expect) expect = f.end;
    }
    return expect;
  }

  maybeComplete() {
    if (this.completed || this.finalEnd === null) return;
    if (!this.sawFirst) return;
    if (this.coverageEnd() < this.finalEnd) return;

    // [0,finalEnd) 已连续覆盖：冻结数据报
    const len = this.finalEnd;
    const data = new Uint8Array(len);
    const origin = new Uint32Array(len);
    const ranges = [];
    const packetsSet = new Set();
    for (const f of this.fragments) {
      packetsSet.add(f.packet);
      ranges.push({ packet: f.packet, lo: f.start, hi: f.end });
      for (let i = f.start; i < f.end; i++) {
        if (origin[i] === 0) {
          data[i] = f.bytes[i - f.start];
          origin[i] = f.packet;
        }
      }
    }
    this.datagram = {
      kind: 'fragment',
      firstPacket: this.firstPacket,
      packetsSet,
      ranges,
      data,
      origin,
    };
    this.completed = true;
  }

  // 最终化一个始终没有首片的“悬空代际”。
  // 它的分片无法用任何已结束数据报一致解释：与前一代际重叠处字节不同 → 覆盖冲突；
  // 越过前一代际封口 → 截断/长度矛盾；否则按缺片（从未出现新首片）拒绝。
  rejectHeadless(prev) {
    if (prev && prev.completed) {
      // 越过封口的片
      for (const f of this.fragments) {
        if (f.end > prev.finalEnd) {
          throw fail('FRAGMENT_CONFLICT',
            `包 ${f.packet} 越过已结束数据报的封口长度 ${prev.finalEnd}（覆盖到偏移 ${f.end}），又没有新的首片（偏移 0）证明标识复用，长度无法一致解释`, {
              packet: Math.min(prev.firstPacket, f.packet),
              packet2: Math.max(prev.firstPacket, f.packet),
              offset: prev.finalEnd,
              range: [prev.finalEnd, f.end],
              extra: { fragmentPackets: this.packetList() },
            });
        }
      }
      // 与前一代际重叠处逐字节核对，定位首个不同字节及其两端包号
      const ordered = [...this.fragments].sort((a, b) => a.start - b.start || a.packet - b.packet);
      for (const f of ordered) {
        const hi = Math.min(f.end, prev.finalEnd);
        for (let i = f.start; i < hi; i++) {
          if (f.bytes[i - f.start] !== prev.datagram.data[i]) {
            let runEnd = i;
            while (runEnd < hi &&
                   f.bytes[runEnd - f.start] !== prev.datagram.data[runEnd]) runEnd++;
            const originPkt = prev.datagram.origin[i];
            const [p1, p2] = originPkt < f.packet ? [originPkt, f.packet] : [f.packet, originPkt];
            throw fail('FRAGMENT_CONFLICT',
              `迟到分片覆盖字节冲突：包 ${p1} 与包 ${p2} 在同一 IP 数据报偏移 ${i} 处字节不同，且没有新的首片（偏移 0）证明标识复用，拒绝覆盖已结束数据报`, {
                packet: p1,
                packet2: p2,
                offset: i,
                range: [i, runEnd],
                extra: { fragmentPackets: this.packetList() },
              });
          }
        }
      }
    }
    // 与前一代际不冲突（或无前代际），但始终没有首片/没收完整：按缺片拒绝
    const expect = this.coverageEnd();
    throw fail('MISSING_FRAGMENT',
      this.finalEnd === null
        ? `IP 分片组（首包 ${this.firstPacket}）缺少末片：偏移 ${expect} 起的数据未捕获，不得用残片拼流`
        : `IP 分片组（首包 ${this.firstPacket}）缺少首片且在偏移 ${expect} 处不连续，标识复用无新首片佐证，不得拼流`,
      {
        packet: this.firstPacket,
        offset: expect,
        range: this.finalEnd === null ? null : [expect, this.finalEnd],
        extra: { fragmentPackets: this.packetList() },
      });
  }

  // 最终化：仍未完整结束的代际按缺片/缺末片拒绝，给出首个包号/偏移/空洞区间
  rejectIfIncomplete(prev) {
    if (this.completed) return;
    if (!this.sawFirst) { this.rejectHeadless(prev); return; }
    const frags = [...this.fragments].sort((a, b) => a.start - b.start || a.packet - b.packet);
    const expect = this.coverageEnd();
    if (this.finalEnd === null) {
      throw fail('MISSING_FRAGMENT',
        `IP 分片组（首包 ${this.firstPacket}）缺少末片：偏移 ${expect} 起的数据未捕获，不得用残片拼流`, {
          packet: this.firstPacket,
          offset: expect,
          range: null,
          extra: { fragmentPackets: this.packetList() },
        });
    }
    let holeEnd = expect;
    let next = null;
    for (const f of frags) {
      if (f.start > expect) { next = f; holeEnd = f.start; break; }
    }
    throw fail('MISSING_FRAGMENT',
      `IP 分片组（首包 ${this.firstPacket}）在数据报偏移 ${expect} 处缺片，存在空洞`, {
        packet: this.firstPacket,
        ...(next ? { packet2: next.packet } : {}),
        offset: expect,
        range: [expect, holeEnd],
        extra: { fragmentPackets: this.packetList() },
      });
  }
}

class FragmentGenerations {
  constructor(key, src, dst) {
    this.key = key;
    this.src = src; // 键已含源/目的，同键所有片一致
    this.dst = dst;
    this.groups = []; // 同键的代际，按出现（首包号）顺序
    this.current = null;
  }

  newGroup(ip) {
    const g = new FragmentGroup(this.key, ip.num);
    this.groups.push(g);
    this.current = g;
    return g;
  }

  add(ip) {
    const start = ip.fragOffset * 8;

    // 优先把片交还给“已封口但未完整”且其区间与本片重叠的代际（从新到旧）：
    // 处理 BEYOND 已另开新代际后，旧代际的迟到补片仍能回到旧代际，而不被新代际吞掉。
    for (let i = this.groups.length - 1; i >= 0; i--) {
      const g = this.groups[i];
      if (!g.completed && g.finalEnd !== null && start < g.finalEnd) {
        g.add(ip); // 越界/异字节在 add 内直接按冲突抛出
        return;
      }
    }

    let g = this.current;
    if (g === null) {
      g = this.newGroup(ip);
      g.add(ip);
      return;
    }

    if (g.completed) {
      // 已结束数据报后的分片：
      //   逐字节相同且不越界（含偏移 0 首片重传）→ 同一数据报的迟到相同重传依据；
      //   否则暂存进一个无首片的新代际，等待新的偏移 0 首片来证明“标识复用”，
      //   新代际自有字节，绝不与历史数据报拼接/逐字节对拍。
      if (g.isIdenticalRetransmit(ip)) { g.absorbDuplicate(ip); return; }
      g = this.newGroup(ip);
    }

    const result = g.add(ip);
    if (result === 'BEYOND') {
      // 开放代际已封口，而本片整片位于封口之后：它不可能属于该代际。
      // 旧代际保留（最终按缺片拒绝），本片另开独立代际处理。
      const ng = this.newGroup(ip);
      ng.add(ip);
    }
  }
}

function conflictRun(aBytes, aOff, bBytes, bOff, lo, hi) {
  let s = lo;
  while (s < hi && aBytes[s - aOff] === bBytes[s - bOff]) s++;
  let e = s;
  while (e < hi && aBytes[e - aOff] !== bBytes[e - bOff]) e++;
  return [s, e];
}

function fragKey(ip) {
  return `${[...ip.src, ...ip.dst, ip.proto, ip.id >>> 8, ip.id & 0xff].join('.')}`;
}

export function reassembleDatagrams(ipPackets) {
  const datagrams = [];
  const generationsByKey = new Map();

  for (const ip of ipPackets) {
    // 未分片的完整数据报：自成一个独立数据报，立即交付（同键标识复用也天然独立）
    if (!ip.mf && ip.fragOffset === 0) {
      datagrams.push({
        kind: 'single',
        firstPacket: ip.num,
        packetsSet: new Set([ip.num]),
        packets: [ip.num],
        ranges: [{ packet: ip.num, lo: 0, hi: ip.payload.length }],
        src: ip.src,
        dst: ip.dst,
        data: ip.payload,
        origin: new Uint32Array(ip.payload.length).fill(ip.num),
      });
      continue;
    }

    const key = fragKey(ip);
    let generations = generationsByKey.get(key);
    if (!generations) {
      generations = new FragmentGenerations(key, ip.src, ip.dst);
      generationsByKey.set(key, generations);
    }
    generations.add(ip);
  }

  // 所有片处理完毕：收集所有未完整结束的代际（无首片的悬空代际需对照同键前一代际
  // 判断是覆盖冲突还是缺片），按首个原始包号全局排序，最早的异常先拒绝。
  const incomplete = [];
  for (const gen of generationsByKey.values()) {
    for (let i = 0; i < gen.groups.length; i++) {
      const g = gen.groups[i];
      if (!g.completed) incomplete.push({ g, prev: i > 0 ? gen.groups[i - 1] : null });
    }
  }
  incomplete.sort((a, b) => a.g.firstPacket - b.g.firstPacket);
  if (incomplete.length > 0) incomplete[0].g.rejectIfIncomplete(incomplete[0].prev);

  for (const gen of generationsByKey.values()) {
    for (const g of gen.groups) {
      const d = g.datagram;
      datagrams.push({
        ...d,
        src: gen.src,
        dst: gen.dst,
        packets: [...d.packetsSet].sort((a, b) => a - b),
      });
    }
  }

  datagrams.sort((a, b) => a.firstPacket - b.firstPacket);
  return datagrams;
}
