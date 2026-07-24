import { Show } from "solid-js";

import { leftTabTitle, rightTabTitle } from "./tabTitles";
import type { BottomTab, HelpState, HelpTopic, LeftTab, RightTab } from "./types";

interface HelpButtonProps {
  topic: HelpTopic;
  onOpen: (state: HelpState) => void;
}

export function HelpButton(props: HelpButtonProps) {
  return (
    <button class="help-btn" type="button" title="帮助" onClick={(event) => {
      const rect = event.currentTarget.getBoundingClientRect();
      const cardW = Math.min(560, window.innerWidth - 24);
      const cardH = Math.min(360, window.innerHeight - 24);
      const spaceBelow = window.innerHeight - rect.bottom - 8;
      const spaceAbove = rect.top - 8;
      const placeAbove = spaceBelow < cardH && spaceAbove > spaceBelow;
      const yRaw = placeAbove ? rect.top - cardH - 8 : rect.bottom + 8;
      const x = Math.max(8, Math.min(rect.left, window.innerWidth - cardW - 8));
      const y = Math.max(8, Math.min(yRaw, window.innerHeight - cardH - 8));
      props.onOpen({ topic: props.topic, x, y });
    }}>?</button>
  );
}

interface HelpPopoverProps {
  state: HelpState | null;
  title: string;
  body: string;
  onClose: () => void;
}

export function HelpPopover(props: HelpPopoverProps) {
  return (
    <Show when={props.state}>
      {(state) => (
        <div class="help-popover" role="dialog" aria-modal="true" onClick={props.onClose}>
          <div class="help-card" style={{ left: `${state().x}px`, top: `${state().y}px` }} onClick={(event) => event.stopPropagation()}>
            <button class="help-close" type="button" onClick={props.onClose}>×</button>
            <h3>{props.title}</h3>
            <p>{props.body}</p>
          </div>
        </div>
      )}
    </Show>
  );
}

export function getHelpTitle(topic: HelpTopic | null, leftTab: LeftTab, rightTab: RightTab, bottomTab: BottomTab): string {
  if (topic === "overview") return "traceMiku Web";
  if (topic === "disasm") return "Disassembly";
  if (topic === "right") return rightTabTitle(rightTab);
  if (topic === "bottom") {
    if (bottomTab === "memory") return "Memory";
    if (bottomTab === "trace-for-pc") return "Trace for PC";
    if (bottomTab === "string-provenance") return "String Provenance";
    if (bottomTab === "query") return "Trace Query";
    return "Navigation";
  }
  return leftTabTitle(leftTab);
}

export function getHelpBody(topic: HelpTopic | null, leftTab: LeftTab, rightTab: RightTab, bottomTab: BottomTab): string {
  if (topic === "overview") return "主界面按调试器布局组织：左侧是函数、回溯、调用树、字符串、污点、Slice 和交叉引用；中间是动态执行过的汇编 trace；下方是内存和当前 PC 的执行历史；右侧是 CFG、寄存器和 HLIL。全局 cursor 就是当前选中的 trace idx，所有窗口都围绕它联动。点击行会设置 cursor；点击寄存器只设置 reg 不跳转；只有双击寄存器或 CFG 单击指令才会移动 cursor。";
  if (topic === "disasm") return "每一行是一条实际执行过的 ARM64 指令快照，不是静态反汇编列表。列含义依次是执行序号、PC、函数+偏移和汇编文本。滚动条对应整个 trace；点击行设置 cursor。寄存器交互：单击 = 选中该寄存器（Taint/Registers 同步）+ 在 dot 列上画一条长箭头连到最近的 def（红 ▲）和 use（绿 ▼），点箭头跳过去；双击寄存器 = 直接跳到 last write；右键寄存器 = 上下文菜单（取值、CFG view、taint）。地址 token 双击跳到最近 PC。Esc 清掉 def/use 箭头。";
  if (topic === "right") {
    if (rightTab === "cfg") return "CFG 显示当前函数的动态基本块图，默认跟随当前 trace 所在函数，避免直接渲染全 trace 导致 dot 超时。空白处拖动平移（拖动期间不会触发 click），按住 Ctrl 滚轮缩放；单击图中的指令或块头会跳到 trace 中离当前 cursor 最近的一次执行——同时联动 Records、Registers、Memory、HLIL、Trace for PC。";
    if (rightTab === "regs") return "寄存器窗口显示当前 cursor 的寄存器状态，并像 pwndbg 一样自动高亮相对上一条 trace 发生变化的寄存器；note 会标出 zero、pc、sp/stack 和疑似指针。点击寄存器会把它设为 Taint/Slice 的当前寄存器（不会跳转 cursor）。";
    if (rightTab === "hlil") return "BN HLIL 通过 Binary Ninja sidecar 提供静态反编译参考。需要配置 TRACEMIKU_BN_SO 环境变量。 时显示 Pseudo C 和 HLIL 两种结构化文本，并高亮当前 PC 对应的行。缩进来自 BN 返回的结构化 indent。点击 HLIL 行会跳到该 PC 在 trace 中离当前 cursor 最近的一次执行。";
    if (rightTab === "pseudoc") return "Decompile 对选中的函数运行三层 decompiler pipeline（LLIL→MLIL→HLIL），展示 HLIL/MLIL/LLIL C 风格伪代码。可以在子标签切换层级。调用参数从 trace 记录中提取实际 x0-x7 寄存器值。records 控制反编译的最大指令数。点 Show decompiled code 加载文本，避免大数据量卡顿。函数边界通过 ret/blr 自动切分。 decompiler pipeline（LLIL→MLIL→HLIL），展示最终 HLIL 的 C 风格伪代码、各层统计信息和覆盖率。选择 Functions 中的函数后自动运行，可调整参与编译的记录数。大输出（500+ 行）默认折叠。";
    if (rightTab === "dec") return "Decompile 显示 traceMiku 本地 Trace IR markdown 和 LLIL render。LLIL records 限制参与渲染的 trace 记录数；DCE 是 Dead Code Elimination，会移除计算结果没有被后续使用的临时语句，适合看更短的伪代码，但排查 lift 细节时可以关闭。这里不调用任何 LLM；模型选择和 LLM 输出暂时不在 UI 中开放。";
    return "";
  }
  if (topic === "bottom") {
    if (bottomTab === "memory") return "Memory 是按调试器习惯排列的 hex+ASCII dump。addr 可以填十六进制地址，也可以填 x0、x1、sp 这类寄存器名；字节颜色表示读、写、外部来源或未知，当前 cursor 发生变化的字节会直接在 dump 中高亮。双击字节跳来源 idx，右键字节显示该地址前后的读写触碰分析。";
    if (bottomTab === "trace-for-pc") return "Trace for PC 显示当前 PC 在 trace 中其它执行位置，分为 cursor 之前和之后。它用来分析循环、调度器、热点指令和同一静态指令在不同时间的状态差异。点击任意行跳转到对应 idx。CFG 单击指令会更新 cursor，本面板自动同步刷新。";
    if (bottomTab === "string-provenance") return "String Provenance 显示 Strings 双击后选中字符串的逐字节来源。上方 String Byte Flow 的含义是 writer trace 写出某个字符字节 → 该字节当前值 → reader trace 读取该字节；为了避免图过密，只展示前 32 个字节和每字节最多 2 个写/读事件。下方表格保留完整 writer/reader 列表，点击 writer#/reader# 会跳到对应 trace。";
    if (bottomTab === "query") return "Trace Query 是统一的结构化查询入口，可查询 records、regs、mem/reads/writes、functions、strings、JNI 和 provenance。命令栏里输入 query writes 0x... len 32、query mem addr 0x... len 32 或 query regs x9 会直接打开这里。";
    return "Navigation 记录本次页面会话里的 cursor 跳转历史，所有来自 Disassembly、CFG、CallTree、Strings、Refs 和 Trace for PC 的跳转都会进入这里。back/forward 只改变 cursor，不重新请求历史。";
  }
  if (leftTab === "funcs") return "Functions 汇总 trace、符号和 BN sidecar 里的函数条目。选择函数会驱动 CFG 和 HLIL；记录数、block 数和入口地址用来判断热函数和分析范围。";
  if (leftTab === "back") return "Backtrace 在当前 cursor 处重建动态调用栈。点击 frame 会跳到对应 call site，用于从深层 JNI/Native 调用回到上游上下文。";
  if (leftTab === "calltree") return "Call Tree 显示整个 trace 的动态嵌套调用关系。定位当前函数按钮会展开并选中包含当前汇编 trace 的函数节点，适合从执行流角度找上下文。";
  if (leftTab === "strings") return "Strings 来自 MemShadow 对内存写入的可打印字符串扫描。单击跳到第一次写入/触碰该字符串地址的 trace；双击会在底部 Provenance 展示每个字符是谁写入、谁读取。";
  if (leftTab === "taint") return "Taint 模拟逐指令的污点传播：从当前 cursor + 寄存器开始，按 trace 顺序一步步推进，可选 through_mem（穿越内存）、cross_fn_call（穿越函数调用）、data_only（只看值流不看地址流）。返回每一行的 parent_idxs / taint_depth，可以画传播树。比 Slice 慢但语义更细——需要看「这个值经过了哪些指令、被哪条指令读/写」时用 Taint。";
  if (leftTab === "slice") return "Slice 在持久化依赖 CSR 上做一次 BFS，比 Taint 快得多。Backward 把当前 cursor 当 sink，列出所有它直接/间接依赖的 trace 行；填第二个 idx + 切到 intersection，会得到两个 cursor 的「共同祖先」（dataflow 交点）。Forward 是反方向 def→use，列出当前行的下游使用者。data only 丢弃控制流依赖。结果按 BFS 发现顺序（单种子）或 idx 升序（多种子求交/并）排列——不是按时间或函数。Slice 不模拟传播过程也没有 through_mem/cross_fn 这些开关；要看传播细节用 Taint。";
  if (leftTab === "xref") return "Refs 上半部分是当前 PC 在 trace 中的其它执行位置；下半部分是按解码后的汇编文本做正则搜索。它不是静态代码引用分析，ret 这类通用指令只有在提交文本搜索后才会列出匹配。";
  if (leftTab === "settings") return "Settings 显示后端 API、MemShadow 状态、密度和调试开关。API debug log 可在需要定位前端/后端交互时打开。";
  if (leftTab === "crypto") return "Crypto 面板整合了三层密码学检测：Memory（MemShadow 字节级常数匹配）、Instructions（trace 指令级立即数/寄存器常数命中，带 Real/ALU/Weak 判定）、Hardware（ARM Crypto Extensions 硬件指令统计）。Summary bar 给出综合判定（Software/Hardware/Mixed/None）。";
  return "SO Filter 用于多 so trace 的折叠、过滤和当前模块聚焦；核心原则是只改变显示范围，不改变 trace 数据本身。";
}
