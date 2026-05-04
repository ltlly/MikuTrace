# Analysis v2 — M4-alpha Implementation Plan (Frontend Cursor Core)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development if available. In Codex sessions where the `superpowers:*` skills are not installed, execute with native tools and keep DONE/BLOCKED reporting.

**Goal:** Add the first M4 frontend core slice around a shared record cursor so the shipped Rust endpoints feel like one analysis workspace, not disconnected panels.

1. Records selection becomes shared app state.
2. Registers, memory, and trace-for-PC panels follow the selected record.
3. The UI consumes only existing Rust v2 endpoints; no new backend routes are required.

**Out of scope:**

- Full IDE-style dock layout.
- BN/HLIL panels.
- Search, xref, forks, settings, or websocket jobs.
- Legacy `webui/` changes.

**Branch:** `refactor/function-index-handoff`. Stream commits.

---

## File Structure

| File | Role |
|---|---|
| `frontend/src/App.tsx` | Own shared selected record index and mount new panels. |
| `frontend/src/api/types.ts` | Add `/api/idxs-for-pc` response type. |
| `frontend/src/api/client.ts` | Add `fetchIdxsForPc`. |
| `frontend/src/panels/records/RecordsPanel.tsx` | Make rows selectable and keyboard reachable. |
| `frontend/src/panels/registers/RegistersPanel.tsx` | New selected-record register table. |
| `frontend/src/panels/memory/MemoryPanel.tsx` | New MemShadow hex dump panel with register address shortcuts. |
| `frontend/src/panels/tracepc/TraceForPcPanel.tsx` | New execution-history panel for selected PC. |
| `frontend/src/styles/base.css` | Dense panel/table styles and selected-row state. |
| `TODO.md` + spec | Mark this M4-alpha slice complete without claiming all M4. |

---

## Task 1: Shared cursor

- [x] Add `selectedIdx` signal in `App.tsx`.
- [x] Pass the cursor to `RecordsPanel` and new cursor-driven panels.
- [x] Records rows select the cursor via click or Enter.

**Commit:** Fold into frontend feature commit.

## Task 2: Cursor-driven panels

- [x] `RegistersPanel` fetches `/api/record/{idx}` and renders PC/asm/regs.
- [x] `MemoryPanel` fetches `/api/mem-dump` and offers selected-record register shortcuts (`x0`..`x3`, `sp` when present).
- [x] `TraceForPcPanel` fetches `/api/idxs-for-pc` for the selected record PC and can jump the shared cursor.

**Commit:** `feat(frontend): add cursor registers memory panels`

## Task 3: Verification and docs

- [x] Run frontend typecheck.
- [x] Run frontend production build.
- [x] Mark M4-alpha done in TODO/spec; leave remaining M4 panels as TODO.

**Verify:**

```bash
cd /home/ltlly/Code/traceMiku/frontend
npm run typecheck
npm run build
```

**Commit:** `docs(v2): mark M4-alpha frontend cursor slice complete`

---

## Self-Review

- [x] No changes to legacy `webui/` or frozen `viewer/app.py`.
- [x] The new panels are endpoint consumers only; backend scope stays unchanged.
- [x] A cursor change updates dependent views without page reload.
- [x] M4 remaining work is still visible in TODO/spec.
