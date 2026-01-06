import type { X64DbgClient } from "../x64dbg/client.js";

type DisasmInstruction = {
  address: number;
  size: number;
  instruction: string;
  branch?: number;
  call?: number;
};

export type CfgEdge = {
  from: number;
  to: number;
  type: "branch" | "call" | "fallthrough";
};

export type CfgBlock = {
  start: number;
  instructions: DisasmInstruction[];
  terminator?: string;
};

export type CfgResult = {
  entry: number;
  blocks: CfgBlock[];
  edges: CfgEdge[];
  truncated: boolean;
};

export type CfgOptions = {
  maxBlocks: number;
  maxInstructions: number;
  maxBlockInstructions: number;
  maxDepth: number;
};

const getMnemonic = (instruction: string): string =>
  instruction.trim().split(/\s+/)[0]?.toLowerCase() ?? "";

const isReturnMnemonic = (mnemonic: string): boolean =>
  mnemonic === "ret" || mnemonic === "retn" || mnemonic === "retf";

const isUnconditionalJump = (mnemonic: string): boolean => mnemonic === "jmp";

const isConditionalJump = (mnemonic: string): boolean =>
  mnemonic.startsWith("j") && mnemonic.length > 1 && mnemonic !== "jmp";

const isStopMnemonic = (mnemonic: string): boolean =>
  mnemonic === "hlt" || mnemonic === "int3";

const formatAddress = (address: number): string => `0x${address.toString(16)}`;

const toInstructions = (value: unknown): DisasmInstruction[] => {
  if (!value || typeof value !== "object") {
    return [];
  }
  const record = value as { instructions?: unknown };
  if (!Array.isArray(record.instructions)) {
    return [];
  }
  return record.instructions.filter(
    (entry): entry is DisasmInstruction =>
      !!entry &&
      typeof (entry as DisasmInstruction).address === "number" &&
      typeof (entry as DisasmInstruction).size === "number" &&
      typeof (entry as DisasmInstruction).instruction === "string"
  );
};

export const buildCfg = async (
  client: X64DbgClient,
  entry: number,
  options: CfgOptions
): Promise<CfgResult> => {
  const queue: Array<{ addr: number; depth: number }> = [
    { addr: entry, depth: 0 }
  ];
  const visited = new Set<number>();
  const blocks: CfgBlock[] = [];
  const edges: CfgEdge[] = [];
  let totalInstructions = 0;
  let truncated = false;

  while (queue.length > 0) {
    const next = queue.shift();
    if (!next) {
      break;
    }
    if (visited.has(next.addr)) {
      continue;
    }
    if (next.depth > options.maxDepth) {
      truncated = true;
      continue;
    }
    if (blocks.length >= options.maxBlocks) {
      truncated = true;
      break;
    }

    visited.add(next.addr);
    const disasmResult = await client.disasm(
      formatAddress(next.addr),
      options.maxBlockInstructions,
      false
    );
    const instructions = toInstructions(disasmResult);
    if (instructions.length === 0) {
      continue;
    }

    const blockInstructions: DisasmInstruction[] = [];
    let terminator: string | undefined;
    for (const instr of instructions) {
      if (totalInstructions >= options.maxInstructions) {
        truncated = true;
        break;
      }
      totalInstructions += 1;
      blockInstructions.push(instr);

      const mnemonic = getMnemonic(instr.instruction);
      const nextAddr = instr.address + instr.size;
      const branchTarget = typeof instr.branch === "number" ? instr.branch : 0;
      const callTarget = typeof instr.call === "number" ? instr.call : 0;

      if (callTarget) {
        edges.push({ from: instr.address, to: callTarget, type: "call" });
      }

      if (isReturnMnemonic(mnemonic) || isStopMnemonic(mnemonic)) {
        terminator = mnemonic;
        break;
      }

      if (isUnconditionalJump(mnemonic)) {
        if (branchTarget) {
          edges.push({
            from: instr.address,
            to: branchTarget,
            type: "branch"
          });
          queue.push({ addr: branchTarget, depth: next.depth + 1 });
        }
        terminator = mnemonic;
        break;
      }

      if (isConditionalJump(mnemonic)) {
        if (branchTarget) {
          edges.push({
            from: instr.address,
            to: branchTarget,
            type: "branch"
          });
          queue.push({ addr: branchTarget, depth: next.depth + 1 });
        }
        edges.push({
          from: instr.address,
          to: nextAddr,
          type: "fallthrough"
        });
        queue.push({ addr: nextAddr, depth: next.depth + 1 });
        terminator = mnemonic;
        break;
      }

      if (instr.size <= 0) {
        break;
      }
    }

    blocks.push({
      start: next.addr,
      instructions: blockInstructions,
      terminator
    });

    const last = blockInstructions[blockInstructions.length - 1];
    if (!terminator && last) {
      const fallthrough = last.address + last.size;
      edges.push({
        from: last.address,
        to: fallthrough,
        type: "fallthrough"
      });
      queue.push({ addr: fallthrough, depth: next.depth + 1 });
    }
  }

  return {
    entry,
    blocks,
    edges,
    truncated
  };
};

export type XrefGraphEdge = {
  from: number;
  to: number;
  type?: string;
};

export type XrefGraphResult = {
  entry: number;
  nodes: number[];
  edges: XrefGraphEdge[];
  truncated: boolean;
};

export type XrefGraphOptions = {
  depth: number;
  maxNodes: number;
  maxEdges: number;
};

export const buildXrefGraph = async (
  client: X64DbgClient,
  entry: number,
  options: XrefGraphOptions
): Promise<XrefGraphResult> => {
  const queue: Array<{ addr: number; depth: number }> = [
    { addr: entry, depth: 0 }
  ];
  const nodes = new Set<number>();
  const edges: XrefGraphEdge[] = [];
  let truncated = false;

  while (queue.length > 0) {
    const next = queue.shift();
    if (!next) {
      break;
    }
    if (nodes.has(next.addr)) {
      continue;
    }
    if (nodes.size >= options.maxNodes) {
      truncated = true;
      break;
    }
    nodes.add(next.addr);

    const xrefResult = await client.getXrefs(formatAddress(next.addr));
    const refs = (xrefResult as { xrefs?: Array<{ address?: number; kind?: string }> })
      .xrefs ?? [];

    for (const ref of refs) {
      if (typeof ref.address !== "number") {
        continue;
      }
      if (edges.length >= options.maxEdges) {
        truncated = true;
        break;
      }
      edges.push({
        from: ref.address,
        to: next.addr,
        type: ref.kind
      });
      if (next.depth + 1 <= options.depth && !nodes.has(ref.address)) {
        queue.push({ addr: ref.address, depth: next.depth + 1 });
      }
    }
    if (truncated) {
      break;
    }
  }

  return {
    entry,
    nodes: Array.from(nodes),
    edges,
    truncated
  };
};
