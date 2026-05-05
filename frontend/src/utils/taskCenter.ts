export type UiTaskStatus = "running" | "ready" | "partial" | "cached" | "cancelled" | "error";

export interface UiTaskUpdate {
  id: string;
  surface: string;
  label: string;
  status: UiTaskStatus;
  detail?: string;
  startedAt?: number;
  endedAt?: number;
}

export interface UiTaskEntry extends UiTaskUpdate {
  startedAt: number;
  updatedAt: number;
  endedAt?: number;
}

export type UiTaskReporter = (update: UiTaskUpdate) => void;
