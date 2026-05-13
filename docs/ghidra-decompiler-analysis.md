# Ghidra Decompiler Architecture Analysis

## Source Tree Layout

```
Ghidra/Features/Decompiler/src/decompile/cpp/   <-- Core decompiler engine (C++)
Ghidra/Features/Decompiler/src/main/java/        <-- Java UI integration layer
```

The C++ core is split into header/implementation pairs. Key files:

- `action.hh/.cc` -- Action/Rule base classes and scheduling infrastructure
- `coreaction.hh/.cc` -- All core Actions (macro transforms) + universal Action construction
- `ruleaction.hh/.cc` -- All transformation Rule classes (fine-grained PcodeOp-level transforms)
- `blockaction.hh/.cc` -- Control-flow structuring + DAG tracing actions
- `block.hh/.cc` -- BlockGraph, FlowBlock, BlockBasic hierarchy
- `op.hh/.cc` -- PcodeOp, PcodeOpBank
- `varnode.hh/.cc` -- Varnode, VarnodeBank
- `variable.hh/.cc` -- HighVariable, VariablePiece, VariableGroup
- `merge.hh/.cc` -- Merge class (Varnode coalescing into HighVariables)
- `funcdata.hh/.cc` -- Funcdata (per-function state), calls CoreAction orchestrator
- `type.hh/.cc` -- Datatype hierarchy (TypePointer, TypeStruct, TypeArray, etc.)
- `modelrules.hh/.cc` -- Struct recovery / data-type matching
- `heritage.hh/.cc` -- SSA construction (phi placement)
- `cover.hh/.cc` -- Cover (range/liveness tracking)
- `flow.hh/.cc` -- BlockFlow computation
- `condexe.hh/.cc` -- Conditional execution (IndirectCollapse)
- `constseq.hh/.cc` -- Constant sequence recognition (strings)
- `bitfield.hh/.cc` -- Bitfield extraction
- `dynamic.hh/.cc` -- Dynamic symbols
- `prefersplit.hh/.cc` -- Variable splitting preferences

---

## Architecture Overview

The decompiler is organized as a **pipeline of Actions**, where each Action is either:

1. **Leaf Action** (`Action` subclass) -- performs one macro-level transformation on the function (e.g., dead code elimination, type inference, SSA construction).
2. **ActionGroup** -- applies child Actions in **sequence**. Has a `rule_repeatapply` flag that causes the entire group to loop until no child makes a change.
3. **ActionRestartGroup** -- like ActionGroup but with a maximum restart count; resets and re-runs children if a restart is requested.
4. **ActionPool** -- a pool of **Rules** that apply simultaneously. For each PcodeOp in the function, it tries every Rule registered for that opcode. The pool is retried repeatedly until fixpoint.

### The "Universal" Action

Every possible action and rule is registered into a single tree called the **universal** action (built in `ActionDatabase::universalAction()`). Named subsets (groups) are derived from the universal via `ActionGroupList`:

```cpp
// Predefined root actions in buildDefaultGroups():
setGroup("decompile", members);   // Full decompilation (default)
setGroup("jumptable", jumptab);   // Jump table analysis
setGroup("normalize", normali);   // Data-flow normalization (no structuring)
setGroup("paramid", paramid);     // Parameter ID analysis
setGroup("register", regmemb);    // Register analysis
setGroup("firstpass", firstmem);  // Minimal first pass
```

### Core Loop

```
ActionRestartGroup("universal", max_restarts=1)
  ActionStart("base")
  [Setup actions]
  ActionGroup("fullloop", repeat_apply)
    ActionGroup("mainloop", repeat_apply)
      [Analysis + simplification + recovery]
      ActionGroup("stackstall", repeat_apply)
        ActionPool("oppool1", repeat_apply)  [~130 rules]
        ActionLaneDivide
        ActionMultiCse
        ActionShadowVar
        ActionDeindirect
        ActionStackPtrFlow
      [Branch cleanup + structure]
      ActionPool("oppool2", repeat_apply)  [PushPtr, StructOffset0, PtrArith, LoadVar, StoreVar]
      [DeterminedBranch + Unreachable + NodeJoin + ConditionalExe + CondConst]
    [Post-loop: LikelyTrash + DeadCode + DoNothing + SwitchNorm + ReturnSplit + ...]
  [Post-fullloop: MappedLocalSync + StartCleanUp]
  ActionPool("cleanup", repeat_apply)  [~15 cleanup rules]
  [PreferComplement + StructureTransform + NormalizeBranches]
  [High-level variable merge pipeline]
  [NameVars + SetCasts + FinalStructure + Stop]
```

---

## Pass Interface

### `Action` (macro-level pass)

```cpp
class Action {
    // Flags:
    rule_repeatapply     // Loop this action (or group) until no change
    rule_onceperfunc     // Apply at most once per function
    rule_oneactperfunc   // Make at most one change per function

    int4 perform(Funcdata &data);  // Entry point (handles status/breakpoint)
    virtual int4 apply(Funcdata &data) = 0;  // Override to implement

    // Change tracking:
    int4 count;           // Cumulative changes
    int4 lcount;          // Changes since last invocation
    // Statistics:
    uint4 count_tests;    // Number of times apply() called
    uint4 count_apply;    // Number of times apply() made changes
};
```

### `Rule` (fine-grained PcodeOp-level transform)

```cpp
class Rule {
    virtual void getOpList(vector<uint4> &oplist) const;
    // ^ Returns list of PcodeOp opcodes this rule triggers on.
    //   Empty list = triggers on ALL ops (global rule).

    virtual int4 applyOp(PcodeOp *op, Funcdata &data);
    // ^ Try to apply at this op. Return non-zero if changed.

    virtual Rule *clone(const ActionGroupList &grouplist) const = 0;
};
```

Rules are pooled into `ActionPool`, which iterates all ops and tries applicable rules until fixpoint.

### Iteration / Fixpoint Pattern

1. `ActionPool::apply()` iterates all PcodeOps in the function (via `PcodeOpTree`).
2. For each op, looks up list of Rules registered for that opcode.
3. Tries each Rule; if any Rule returns non-zero, restarts pool iteration from beginning.
4. Continues until full pass yields no changes (`lcount == 0`).
5. Wrapping `ActionGroup(rule_repeatapply)` causes the group to loop until ALL contained actions converge.
6. The `mainloop` and `stackstall` groups both have `rule_repeatapply`, creating nested fixpoints.

---

## Complete List of Core Actions

### Setup Actions (Phase 0)

| Action | Group | Description |
|--------|-------|-------------|
| `ActionStart` | base | Initialize function processing. Entry point |
| `ActionStop` | base | Post-processing cleanup/teardown |
| `ActionConstbase` | base | Inject constant values for tracked registers at function entry |
| `ActionNormalizeSetup` | normalanalysis | Unlock input/output symbols for normalize mode |
| `ActionDefaultParams` | base | Load/modify sub-function prototypes, inject uponreturn p-code |
| `ActionExtraPopSetup` | base | Insert p-code relationships between pre/post-call stack ptrs |
| `ActionPrototypeTypes` | protorecovery | Lay down locked input/output data-types, build forced Varnodes |
| `ActionFuncLink` | protorecovery | Link sub-function parameters (known prototypes) |
| `ActionFuncLinkOutOnly` | noproto | Link only outputs for unknown prototypes |

### Main Loop Actions (Phase 1, repeat until fixpoint)

| Action | Group | Description |
|--------|-------|-------------|
| `ActionUnreachable` | base | Remove unreachable basic blocks |
| `ActionVarnodeProps` | base | Convert read-only to constants, handle volatile, replace unconsumed with 0 |
| `ActionHeritage` | base | Build SSA form: place phi nodes (MULTIEQUAL), propagate copies |
| `ActionParamDouble` | protorecovery | Handle double-precision-like parameter concatenation |
| `ActionSegmentize` | base | Convert segment p-code ops to CPUI_SEGMENTOP |
| `ActionInternalStorage` | base | Mark constants stored from internal compiler registers as non-addressable |
| `ActionForceGoto` | blockrecovery | Apply forced-goto overrides |
| `ActionDirectWrite` | protorecovery_a/b | Propagate 'directwrite' attribute (legal params), with/without INDIRECT |
| `ActionActiveParam` | protorecovery | Determine which Varnodes are active parameters to sub-functions |
| `ActionReturnRecovery` | protorecovery | Determine data-flow holding the return value |
| `ActionRestrictLocal` | localrecovery | Mark parameters and unaffected stores to prevent local-variable assignment |
| `ActionDeadCode` | deadcode | Bit-level dead code elimination via back-propagation of 'consumed' mask |
| `ActionDynamicMapping` | dynamic | Attach dynamically mapped symbols to Varnodes |
| `ActionRestructureVarnode` | localrecovery | Create stack frame symbols, map out local variables |
| `ActionSpacebase` | base | Mark Varnodes holding stack-pointer values, set up special data-type |
| `ActionNonzeroMask` | analysis | Calculate non-zero mask property on all Varnodes |
| `ActionInferTypes` | typerecovery | Propagate data-types through the data-flow graph (DFS fixpoint) |

### Simplification Pool (stackstall sub-pipeline)

The stackstall group wraps:
1. **ActionPool("oppool1")** -- ~130 rules (see below)
2. `ActionLaneDivide` -- Split vectorized lane registers
3. `ActionMultiCse` -- CSE for MULTIEQUAL (phi) ops
4. `ActionShadowVar` -- Check for MULTIEQUAL defining multiple Varnodes
5. `ActionDeindirect` -- Eliminate locally-constant indirect calls
6. `ActionStackPtrFlow` -- Analyze stack pointer changes across calls

### Post-Simplification Actions (still in mainloop)

| Action | Group | Description |
|--------|-------|-------------|
| `ActionRedundBranch` | deadcontrolflow | Remove duplicate edges between same blocks |
| `ActionBlockStructure` | blockrecovery | Structuring pass (CollapseStructure algorithm) |
| `ActionConstantPtr` | typerecovery | Convert constants with pointer type to global symbol refs |
| `ActionPool("oppool2")` | -- | Pointer/subvar rules (PushPtr, StructOffset0, PtrArith, LoadVarnode, StoreVarnode) |
| `ActionDeterminedBranch` | unreachable | Remove constant-condition branches |
| `ActionUnreachable` | unreachable | Remove newly-unreachable blocks |
| `ActionNodeJoin` | nodejoin | Merge split conditional branches |
| `ActionConditionalExe` | conditionalexe | Handle conditional move / conditional execution |
| `ActionConditionalConst` | analysis | Propagate constants along conditional branches |

### Post-Mainloop Actions

| Action | Group | Description |
|--------|-------|-------------|
| `ActionLikelyTrash` | protorecovery | Remove likely-trash register values |
| `ActionDirectWrite` | protorecovery | Re-run directwrite propagation |
| `ActionDeadCode` | deadcode | Re-run DCE after transformations |
| `ActionDoNothing` | deadcontrolflow | Remove blocks that only contain COPY-to-self |
| `ActionSwitchNorm` | switchnorm | Normalize switch/jump-table analysis |
| `ActionReturnSplit` | returnsplit | Split epilog into individual RETURN ops |
| `ActionUnjustifiedParams` | protorecovery | Fix improperly justified parameters |
| `ActionStartTypes` | typerecovery | Mark function to allow data-type recovery to start |
| `ActionActiveReturn` | protorecovery | Determine which sub-functions have active outputs |

### Cleanup Actions (Phase 2)

| Action | Group | Description |
|--------|-------|-------------|
| `ActionMappedLocalSync` | localrecovery | Push local scope data-types onto Varnodes |
| `ActionStartCleanUp` | cleanup | Mark end of main transform, begin cleanup |

### Cleanup Pool (ActionPool)

| Rule | Description |
|------|-------------|
| `RuleMultNegOne` | `x * -1` -> `-x` |
| `RuleAddUnsigned` | Propagate unsigned property through ADD |
| `Rule2Comp2Sub` | `2-comp` -> `0 - x` |
| `RuleSubRight` | `(x + y) - z` -> `x + (y - z)` |
| `RuleFloatSignCleanup` | Clean up float sign encoding |
| `RuleExpandLoad` | Expand LOAD into more explicit component accesses |
| `RulePtrsubCharConstant` | Push constants through PTRSUB |
| `RuleExtensionPush` | Push zero/sign extensions through ops |
| `RulePieceStructure` | Reconstruct struct/array accesses from SUBPIECE patterns |
| `RuleSplitCopy` | Split copy chains |
| `RuleSplitLoad/Store` | Split pointer loads/stores |
| `RuleStringCopy/Store` | String constant recognition |
| `RuleBitFieldStore/Out/Load/In` | Bitfield pattern recognition |
| `RulePullAbsorb/InsertAbsorb` | Bitfield absorption |

### Post-Cleanup Actions (Phase 3)

| Action | Group | Description |
|--------|-------|-------------|
| `ActionPreferComplement` | blockrecovery | Choose between symmetric structurings (if/else swap) |
| `ActionStructureTransform` | blockrecovery | Final structure transforms (for-loop setup via BlockWhileDo) |
| `ActionNormalizeBranches` | normalizebranches | Flip branches to preferred comparison form (alternative to structuring) |
| `ActionAssignHigh` | merge | Assign initial HighVariable objects to each Varnode |
| `ActionMergeRequired` | merge | Merge Varnodes forced by MULTIEQUAL, INDIRECT, addrtied |
| `ActionMarkExplicit` | merge | Determine which Varnodes become explicit variables in output |
| `ActionMarkImplied` | merge | Mark temporary Varnodes that have no explicit token |
| `ActionMergeMultiEntry` | merge | Merge Varnodes from multi-entry symbols |
| `ActionMergeCopy` | merge | Merge COPY op input/output Varnodes |
| `ActionDominantCopy` | merge | Replace multiple copies from same source with single dominant COPY |
| `ActionDynamicSymbols` | dynamic | Final attachment of dynamically mapped symbols |
| `ActionMarkIndirectOnly` | merge | Flag Varnodes only used in INDIRECT ops |
| `ActionMergeAdjacent` | merge | Merge same-location Varnodes through an op |
| `ActionMergeType` | merge | Speculative merge by data-type (non-overlapping covers) |
| `ActionHideShadow` | merge | Hide shadow Varnode copies |
| `ActionCopyMarker` | merge | Mark internal copies as non-printing |
| `ActionOutputPrototype` | localrecovery | Formalize output data-type in prototype |
| `ActionInputPrototype` | fixateproto | Discover and set parameter types |
| `ActionMapGlobals` | fixateglobals | Create symbols for discovered globals |
| `ActionNameVars` | merge | Choose names for all HighVariables |
| `ActionSetCasts` | casts | Insert explicit cast p-code ops |
| `ActionFinalStructure` | blockrecovery | Label goto edges, order switch cases, order disjoint components |
| `ActionPrototypeWarnings` | protorecovery | Warn about poorly modeled prototypes |

---

## Complete List of Rules (all ~130 in oppool1)

### Dead Code / Early Removal
- `RuleEarlyRemoval` -- Remove dead branches

### Normalization / Algebraic Simplification
- `RuleTermOrder` -- Canonicalize operand ordering (constants to right, etc.)
- `RuleCollectTerms` -- Build PTRADD/PTRSUB from ADD of pointer + offset expression
- `RuleSelectCse` -- Detect common subexpressions
- `RulePullsubMulti` -- Pull SUBPIECE backwards through MULTIEQUAL
- `RulePullsubIndirect` -- Pull SUBPIECE backwards through INDIRECT
- `RulePushMulti` -- Push common Varnode backwards through MULTIEQUAL

### Carry / Borrow Elimination
- `RuleSborrow`, `RuleScarry` -- Signed borrow/carry simplification
- `RuleCarryElim` -- Eliminate carry operations that are only compared to 0

### Comparison -> Boolean
- `RuleIntLessEqual`, `RuleLessOne` -- `INT_LESSEQUAL(0)` -> `INT_EQUAL(0)`
- `RuleLess2Zero`, `RuleLessEqual2Zero`, `RuleSLess2Zero`, `RuleEqual2Zero`, `RuleEqual2Constant`
- `RuleLessEqual`, `RuleLessNotEqual` -- Invert/commute comparisons
- `RuleCondNegate`, `RuleBoolNegate` -- Negate boolean conditions
- `RuleInt2FloatCollapse`, `RuleFloatCast`, `RuleFloatSign`, `RuleFloatSignCleanup`

### Shift / Bitwise
- `RuleTrivialShift`, `RuleSignShift`, `RuleTestSign`, `RuleShiftBitops`, `RuleRightShiftAnd`
- `RuleShift2Mult`, `RuleShiftPiece`, `RuleShiftCompare`, `RuleShiftAnd`
- `RuleDoubleSub`, `RuleDoubleShift`, `RuleDoubleArithShift`, `RuleConcatShift`
- `RuleLeftRight`, `RuleConcatZero`, `RuleConcatLeftShift`, `RuleConcatZext`
- `RuleHighOrderAnd`, `RuleAndDistribute`, `RuleAndCommute`, `RuleAndPiece`, `RuleAndZext`, `RuleAndCompare`
- `RuleNotDistribute`, `RuleBitUndistribute`

### Arithmetic
- `RuleTrivialArith`, `RuleTrivialBool`, `RuleCollapseConstants`
- `Rule2Comp2Mult`, `RuleSub2Add`, `RuleAddMultCollapse`, `RuleXorCollapse`
- `RuleNegateIdentity`, `RuleIdentityEl`
- `RuleOrMask`, `RuleAndMask`, `RuleOrConsume`, `RuleOrCollapse`, `RuleAndOrLump`
- `RuleBxor2NotEqual`, `RulePiece2Zext`, `RulePiece2Sext`

### Extension / Truncation
- `RuleZextEliminate`, `RuleZextSless`, `RuleSlessToLess`, `RuleZextCommute`, `RuleZextShiftZext`
- `RuleSubExtComm`, `RuleSubCommute`, `RuleSubZext`, `RuleSubCancel`, `RuleShiftSub`
- `RuleSubNormal`, `RuleConcatCommute`, `RuleHumptyDumpty`, `RuleDumptyHump`, `RuleHumptyOr`

### Boolean / Logic
- `RuleBooleanUndistribute`, `RuleBooleanDedup`, `RuleBooleanNegate`, `RuleBoolZext`, `RuleLogic2Bool`
- `RulePopcountBoolXor`, `RuleLzcountShiftBool`

### Division / Modulo Optimization
- `RulePositiveDiv`, `RuleDivTermAdd`, `RuleDivTermAdd2`, `RuleDivOpt`, `RuleSignDiv2`
- `RuleDivChain`, `RuleSignForm`, `RuleSignForm2`, `RuleSignNearMult`
- `RuleModOpt`, `RuleSignMod2nOpt`, `RuleSignMod2Opt`, `RuleSignMod2nOpt2`

### Switch / Conditional
- `RuleSwitchSingle` -- Convert single-case switch
- `RuleConditionalMove` -- Convert if-else to conditional expression
- `RuleThreeWayCompare` -- Recognize three-way comparison patterns
- `RuleXorSwap` -- XOR swap pattern

### Pointer / Struct
- `RulePtraddUndo`, `RulePtrsubUndo` -- Reverse PTRADD/PTRSUB into ADD/SUB
- `RulePushPtr` -- Propagate pointer constants through PTRSUB/PTRADD
- `RuleStructOffset0` -- Eliminate PTRSUB with offset 0
- `RulePtrArith` -- Pointer arithmetic identification
- `RuleLoadVarnode`, `RuleStoreVarnode` -- Convert LOAD/STORE with spacebase to direct access
- `RulePtrFlow` -- Propagate pointer flow through indirect paths
- `RuleSegment` -- Handle segmented address spaces
- `RuleCollectTerms` -- Build PTRADD/PTRSUB from ADD tree

### Float
- `RuleFloatCast`, `RuleIgnoreNan`, `RuleUnsigned2Float`, `RuleInt2FloatCollapse`
- `RuleFloatRange`, `RuleFloatSign`, `RuleFloatSignCleanup`
- `RuleOrCompare`, `RuleOrPredicate`
- `RuleSubfloatConvert`, `RuleFuncPtrEncoding`
- `RuleDoubleLoad/Store/In/Out` -- Double precision patterns

### Subvariable (oppool1, group "subvar")
- `RuleSubvarAnd` -- Eliminate AND mask for subvariable extraction
- `RuleSubvarSubpiece` -- Simplify SUBPIECE of known subvariable
- `RuleSplitFlow` -- Split variable across branches
- `RuleSubvarCompZero`, `RuleSubvarShift`, `RuleSubvarZext`, `RuleSubvarSext`

### Cleanup Rules (oppool3, group "cleanup")
See cleanup pool above.

---

## Key Data Structures

### PcodeOp (op.hh)
The fundamental operation in p-code IR. Each op has:
- A **unique sequence number** (`SeqNum`: address + order)
- An **opcode** from the `OpCode` enum (CPUI_COPY, CPUI_LOAD, CPUI_STORE, etc.)
- Exactly **one output** Varnode (except control-flow ops)
- **Multiple input** Varnodes (all same size)
- Boolean **flags**: startbasic, branch, call, returns, dead, marker, etc.
- Links: `prev`/`next` in basic block, `insertBefore`/`insertAfter`

### Varnode (varnode.hh)
The fundamental variable in p-code:
- Described by **Address** (space + offset) + **size in bytes**
- In SSA form: unique instance per write (multiple Varnodes can share same Address)
- Boolean **flags**: constant, input, written, implied, explicit, typelock, addrtied, etc.
- Has a **defining PcodeOp** (or is an input)
- Has list of **descendant PcodeOps** (uses)
- Has a **data-type** (Datatype pointer)
- Has **non-zero mask** (which bits are known non-zero)
- Has **cover** (range where the value is live)

### HighVariable (variable.hh)
A high-level variable = list of Varnodes (each written at most once, in SSA):
- Varnodes are merged if their covers do not intersect
- Inherits cover = union of member Varnode covers
- Has a representative data-type
- Supports `VariablePiece` / `VariableGroup` for overlapping symbols

### Funcdata (funcdata.hh)
Per-function state:
- PcodeOpBank (all ops), VarnodeBank (all varnodes)
- BlockGraph (control-flow hierarchy)
- Symbol table (local/global symbols)
- Prototype info (inputs, outputs, model)
- Merge state, type factory, high-level variable table
- Restart pending flag
- Maps from address to code, op iteration support

### Datatype Hierarchy (type.hh)
- `type_metatype`: TYPE_VOID, TYPE_SPACEBASE, TYPE_INT, TYPE_UINT, TYPE_BOOL, TYPE_CODE, TYPE_FLOAT, TYPE_STRUCT, TYPE_PTR, TYPE_ARRAY, TYPE_UNION, etc.
- `Datatype` base with size, metatype, name
- `TypePointer` -- pointer with pointed-to type
- `TypeStruct` -- structure with fields
- `TypeArray` -- array with element type and count

---

## PcodeOp Opcodes (opcodes.hh)

P-code is Ghidra's register-transfer-level IR. All operations are explicit about size and side effects.

| Category | Opcodes |
|----------|---------|
| Copy/Load/Store | COPY(1), LOAD(2), STORE(3) |
| Control Flow | BRANCH(4), CBRANCH(5), BRANCHIND(6), CALL(7), CALLIND(8), CALLOTHER(9), RETURN(10) |
| Integer Compare | INT_EQUAL(11), INT_NOTEQUAL(12), INT_SLESS(13), INT_SLESSEQUAL(14), INT_LESS(15), INT_LESSEQUAL(16) |
| Integer Convert | INT_ZEXT(17), INT_SEXT(18) |
| Integer Arithmetic | INT_ADD(19), INT_SUB(20), INT_CARRY(21), INT_SCARRY(22), INT_SBORROW(23), INT_2COMP(24), INT_NEGATE(25) |
| Integer Bitwise | INT_XOR(26), INT_AND(27), INT_OR(28) |
| Integer Shift | INT_LEFT(29), INT_RIGHT(30), INT_SRIGHT(31) |
| Integer Mult/Div | INT_MULT(32), INT_DIV(33), INT_SDIV(34), INT_REM(35), INT_SREM(36) |
| Boolean | BOOL_NEGATE(37), BOOL_XOR(38), BOOL_AND(39), BOOL_OR(40) |
| Float Compare | FLOAT_EQUAL(41), FLOAT_NOTEQUAL(42), FLOAT_LESS(43), FLOAT_LESSEQUAL(44), FLOAT_NAN(46) |
| Float Arithmetic | FLOAT_ADD(47), FLOAT_DIV(48), FLOAT_MULT(49), FLOAT_SUB(50), FLOAT_NEG(51), FLOAT_ABS(52), FLOAT_SQRT(53) |
| Float Convert | FLOAT_INT2FLOAT(54), FLOAT_FLOAT2FLOAT(55), FLOAT_TRUNC(56), FLOAT_CEIL(57), FLOAT_FLOOR(58), FLOAT_ROUND(59) |
| SSA/High-Level | MULTIEQUAL(60) [phi], INDIRECT(61) [side-effect], PTRADD(62), PTRSUB(63), PIECE(64), SUBPIECE(65) |
| Cast | CAST(66) [type cast annotation], MULTIEQUAL_NEW(67) |

---

## Control Flow Structuring (blockaction.hh)

The structuring algorithm is in `CollapseStructure` (called by `ActionBlockStructure`):

1. **Loop Detection**: Identify natural loops via back edges (Tarjan-style). Build `LoopBody` objects with head, tail(s), exit block.
2. **Ordering**: Nested loops are processed innermost-first.
3. **Collapse**: For each innermost loop, repeatedly apply pattern-matching rules:
   - `ruleBlockGoto` -- Mark unstructured edge as goto
   - `ruleBlockCat` -- Concatenate blocks into BlockList
   - `ruleBlockOr` -- Merge conditional paths into BlockCondition
   - `ruleBlockProperIf` -- If-then (2-component)
   - `ruleBlockIfElse` -- If-then-else (3-component)
   - `ruleBlockIfNoExit` -- If without exit
   - `ruleBlockWhileDo` -- While loop
   - `ruleBlockDoWhile` -- Do-while loop
   - `ruleBlockInfLoop` -- Infinite loop
   - `ruleBlockSwitch` -- Switch/case
   - `ruleCaseFallthru` -- Fall-through cases
4. **When stuck**: Use `TraceDAG` to identify minimal unstructured edges (most "goto-like" edges). Remove those edges and retry.
5. **Final**: `ActionFinalStructure` labels goto edges, orders switch cases, orders disjoint components.

### Return Split

`ActionReturnSplit` splits shared epilog blocks into individual RETURN ops per path, enabling better structuring of multi-return functions.

---

## Struct Recovery Approach

Struct recovery happens at multiple levels:

1. **Stack frame reconstruction** (`ActionRestructureVarnode`): Analyzes stack pointer-relative accesses, groups them by offset, creates local symbols with inferred types.

2. **Pointer arithmetic pattern matching** (`RuleCollectTerms`, `RulePtrArith`, `RulePushPtr`): Converts raw ADD trees into PTRADD/PTRSUB operations with explicit base type + offset + element count.

3. **Load/store splitting** (`RuleLoadVarnode`, `RuleStoreVarnode`): Converts LOAD/STORE with spacebase-relative addresses into direct Varnode references.

4. **Piece-based reconstruction** (`RulePieceStructure`): Detects when a Varnode is pieced together from smaller SUBPIECE operations and reconstructs the original structure/array access.

5. **Bitfield recognition** (`RuleBitFieldStore/Out/Load/In/`): Detects shift-and-mask patterns that correspond to bitfield accesses.

6. **String recognition** (`RuleStringCopy/Store`): Detects constant sequences stored byte-by-byte into contiguous memory.

7. **Model rules** (`modelrules.cc`): Configured via `.cspec` XML, define patterns for struct field matching, array determination, and type propagation heuristics.

---

## Type Propagation Approach

Implemented in `ActionInferTypes` (coreaction.hh):

1. **Build local types**: Every Varnode gets an initial data-type based on PcodeOp requirements (function inputs from prototype, constants from their value, etc.).

2. **Propagate via edges**: Type propagates through:
   - COPY (direct)
   - LOAD/STORE (pointer type propagates to pointed-to type)
   - ADD (pointer arithmetic preserves pointed-to type)
   - MULTIEQUAL (phi nodes merge types)
   - INDIRECT (side-effect nodes merge types)
   - PTRADD/PTRSUB (base pointer type propagates)

3. **DFS fixpoint**: Each Varnode gets one chance to propagate to the whole graph. Types are ordered from most-specified to least-specified. A Varnode that has already received a higher type stops propagation. This is theoretically quadratic but linear in practice.

4. **Write-back**: After propagation converges (or iteration limit reached), commit types back to Varnodes.

5. **Feedback loop**: Type propagation feeds struct recovery, which creates new symbols with types, which feed back into type propagation (with iteration limit guard).

---

## Design Patterns to Replicate in Our MLIL/HLIL

### 1. Action Pipeline Architecture
- Use a nested group/action pattern with `rule_repeatapply` fixpoint loops.
- Separate **macro transformations** (Actions) from **micro transformations** (Rules).
- Rules register for specific opcodes via `getOpList()`.
- Pool rules together with a top-level fixpoint loop.

### 2. Fixpoint Pattern
```
while changed:
    for each op in function:
        for each applicable rule:
            if rule.apply(op): changed = true; restart
```
Nested fixpoints: inner pool converges first, then outer group checks for higher-level convergence.

### 3. Varnode/PcodeOp Equivalents for MLIL
Our MLIL needs:
- **SsaVar** = Varnode equivalent: (definition, uses, type, size, constant value)
- **SsaOp** = PcodeOp equivalent: (opcode, output, inputs, flags)
- **PhiNode** = MULTIEQUAL equivalent for SSA merge points
- **Cover** = range/liveness tracking for variable merging
- **HighVariable** = our merged variable after coalescing

### 4. Graduated Analysis Phases
- Phase 0: Setup (prototypes, parameters, SSA building)
- Phase 1: Simplify + recover (type propagation, struct recovery, while data-flow changes)
- Phase 2: Clean up (normalization, string/bitfield detection)
- Phase 3: High-level merge (coalesce Varnodes into user-visible variables, name them)
- Phase 4: Structuring (control-flow graph -> structured statements)
- Phase 5: Finalize (casts, output, warnings)

### 5. Type Propagation Strategy
- Propagate types along COPY/LOAD/STORE/MULTIEQUAL edges using ordered type lattice
- Use DFS from highest-type Varnodes first
- Cap iterations to prevent non-convergence in feedback loops

### 6. Struct Recovery Strategy
- Pattern-match ADD trees into pointer arithmetic (PTRADD/PTRSUB)
- Detect contiguous byte accesses as structure/array field accesses
- Recognize shift-and-mask as bitfields
- Recognize byte-by-byte stores as string constants

### 7. Control Flow Structuring
- Identify loops via back edges (innermost-first)
- Collapse using pattern matching (if, if-else, while, do-while, switch)
- When stuck, use DAG tracing to identify minimal unstructured edges
- Split shared returns before structuring for better results

### 8. Variable Merging for HLIL
- Varnodes at the same storage location with non-overlapping covers can merge into one variable
- Required merges: phi nodes, INDIRECT ops, address-tied variables
- Speculative merges: group by data-type when covers don't intersect

---

## Dependency Graph / Ordering Constraints

Key ordering dependencies documented in code comments:

1. `ActionActiveParam` must run AFTER `ActionHeritage` and `ActionDirectWrite` but BEFORE simplification/copy propagation.
2. `ActionRestrictLocal` must run BEFORE `ActionDeadCode`.
3. `ActionDynamicMapping` must come BEFORE `ActionRestructureVarnode` and `ActionInferTypes`.
4. `ActionSpacebase` must come BEFORE `ActionInferTypes` and `ActionNonzeroMask`.
5. `ActionMarkImplied` must come BEFORE general merging (in phase 3).
6. `ActionMarkIndirectOnly` must come AFTER required merges but BEFORE speculative merges.
7. `ActionStackPtrFlow` needs to be in a repeat loop because it may trigger changes.

## Group Partitioning

Actions and Rules are assigned to named groups. The `buildDefaultGroups()` defines six root actions:

- **decompile**: base, protorecovery, protorecovery_a, deindirect, localrecovery, deadcode, typerecovery, stackptrflow, blockrecovery, stackvars, deadcontrolflow, switchnorm, cleanup, splitcopy, splitpointer, merge, dynamic, casts, analysis, fixateglobals, fixateproto, constsequence, bitfields, segment, returnsplit, nodejoin, doubleload, doubleprecis, unreachable, subvar, floatprecision, conditionalexe

When an Action or Rule is cloned, its group is checked against the active grouplist. Only members of groups in the current root action are included. This is how different decompilation modes (decompile vs normalize vs jumptable) selectively activate subsets of the full universal.
