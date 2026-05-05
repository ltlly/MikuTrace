import { For, Show } from "solid-js";

export interface ProvNode {
  id: string;
  label: string;
  sub?: string;
  kind?: "seed" | "record" | "memory" | "string" | "writer" | "reader" | "value";
  onClick?: () => void;
}

export interface ProvEdge {
  from: string;
  to: string;
  label?: string;
}

interface ProvenanceGraphProps {
  title: string;
  nodes: ProvNode[];
  edges: ProvEdge[];
  empty?: string;
  summary?: string;
  note?: string;
}

export default function ProvenanceGraph(props: ProvenanceGraphProps) {
  const nodeById = () => new Map(props.nodes.map((node) => [node.id, node]));
  return (
    <div class="prov-graph">
      <div class="prov-graph-head">
        <b>{props.title}</b>
        <span class="dim small">{props.summary ?? `${props.nodes.length} items · ${props.edges.length} links`}</span>
      </div>
      <Show when={props.note}>
        <p class="prov-graph-note">{props.note}</p>
      </Show>
      <Show when={props.nodes.length > 0} fallback={<p class="dim small">{props.empty ?? "no provenance edges"}</p>}>
        <div class="prov-graph-body">
          <div class="prov-node-list">
            <For each={props.nodes}>
              {(node) => (
                <button
                  type="button"
                  class="prov-node"
                  classList={{ clickable: !!node.onClick, [node.kind ?? "value"]: true }}
                  onClick={() => node.onClick?.()}
                  disabled={!node.onClick}
                >
                  <span>{node.label}</span>
                  <Show when={node.sub}>
                    <small>{node.sub}</small>
                  </Show>
                </button>
              )}
            </For>
          </div>
          <div class="prov-edge-list">
            <For each={props.edges}>
              {(edge) => {
                const from = nodeById().get(edge.from);
                const to = nodeById().get(edge.to);
                return (
                  <div class="prov-edge">
                    <code>{from?.label ?? edge.from}</code>
                    <span>→</span>
                    <code>{to?.label ?? edge.to}</code>
                    <Show when={edge.label}>
                      <small>{edge.label}</small>
                    </Show>
                  </div>
                );
              }}
            </For>
          </div>
        </div>
      </Show>
    </div>
  );
}
