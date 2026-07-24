
interface TabButtonProps {
  tab: string;
  label: string;
  active: boolean;
  title?: string;
  side: "left" | "right" | "bottom";
  onSelect: () => void;
}

export function TabButton(props: TabButtonProps) {
  if (props.side === "bottom") return <button class="btab" data-btab={props.tab} classList={{ active: props.active }} onClick={props.onSelect}>{props.label}</button>;
  return <button class="vtab" data-vtab={props.side === "left" ? props.tab : undefined} data-rtab={props.side === "right" ? props.tab : undefined} classList={{ active: props.active }} title={props.title} onClick={props.onSelect}>{props.label}</button>;
}
