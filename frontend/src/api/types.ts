/** Wire contract: docs/superpowers/specs/2026-05-03-meta-endpoint-contract.md
 *  M1 hand-writes this; M3 will replace with openapi-typescript codegen. */
export interface ModuleInfo {
  name: string;
  base: string;
  size: number;
  end: string;
}

export interface MetaResponse {
  path: string;
  records: number;
  module: ModuleInfo | null;
  modules: ModuleInfo[];
  method: string;
  cmd: number | null;
  fn_addr: string | null;
  regs: string[];
}
