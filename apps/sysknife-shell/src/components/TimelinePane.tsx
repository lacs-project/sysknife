import { useEffect, useRef } from "react";
import type { TimelineEntry, TimelineEntryKind } from "../shellState";

interface Props {
  entries: TimelineEntry[];
}

const KIND_COLORS: Record<TimelineEntryKind, string> = {
  system:  "#9db0ff",
  user:    "#8ca2ff",
  success: "#4ade80",
  warning: "#fb923c",
  error:   "#f87171",
};

export function TimelinePane({ entries }: Props) {
  const bottomRef = useRef<HTMLLIElement>(null);

  useEffect(() => {
    if (bottomRef.current && typeof bottomRef.current.scrollIntoView === "function") {
      bottomRef.current.scrollIntoView({ behavior: "smooth", block: "end" });
    }
  }, [entries]);

  return (
    <section className="pane pane-timeline">
      <h2>Timeline</h2>
      <ol className="timeline" aria-live="polite" aria-label="Event log">
        {entries.length === 0 && <li className="timeline-empty">No events yet</li>}
        {entries.map((entry, i) => (
          <li
            key={entry.id}
            className="timeline-entry"
            ref={i === entries.length - 1 ? bottomRef : null}
          >
            <span
              className="timeline-entry__dot"
              style={{ color: KIND_COLORS[entry.kind] }}
              aria-hidden
            >
              ●
            </span>
            <time className="timeline-entry__timestamp">{entry.timestamp}</time>
            <span className="timeline-entry__text">{entry.text}</span>
          </li>
        ))}
      </ol>
    </section>
  );
}
