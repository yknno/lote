const instances = new Set();
let ticker = null;

function pad2(n) {
  return String(n).padStart(2, "0");
}

function isSameLocalDay(a, b) {
  return (
    a.getFullYear() === b.getFullYear() &&
    a.getMonth() === b.getMonth() &&
    a.getDate() === b.getDate()
  );
}

function formatLocalTime(date, now) {
  const hhmm = `${pad2(date.getHours())}:${pad2(date.getMinutes())}`;
  if (isSameLocalDay(date, now)) {
    return hhmm;
  }
  const mmdd = `${pad2(date.getMonth() + 1)}/${pad2(date.getDate())}`;
  if (date.getFullYear() === now.getFullYear()) {
    return `${mmdd} ${hhmm}`;
  }
  return `${date.getFullYear()}-${pad2(date.getMonth() + 1)}-${pad2(date.getDate())} ${hhmm}`;
}

function formatRelative(diffSec) {
  if (diffSec < -60) return null;
  if (diffSec < 60) return "just now";
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
  if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
  if (diffSec < 86400 * 7) return `${Math.floor(diffSec / 86400)}d ago`;
  return null;
}

const fullFormatter = new Intl.DateTimeFormat(undefined, {
  year: "numeric",
  month: "2-digit",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hourCycle: "h23",
  timeZoneName: "short",
});

export function formatPostTimestamp(date, now = new Date()) {
  const diffSec = Math.floor((now.getTime() - date.getTime()) / 1000);
  const local = formatLocalTime(date, now);
  const rel = formatRelative(diffSec);
  return {
    text: rel ? `${rel} · ${local}` : local,
    title: fullFormatter.format(date),
  };
}

function startTicker() {
  if (ticker !== null) return;
  ticker = window.setInterval(() => {
    const now = new Date();
    for (const el of instances) {
      el.render(now);
    }
  }, 30_000);
}

function stopTickerIfIdle() {
  if (instances.size === 0 && ticker !== null) {
    window.clearInterval(ticker);
    ticker = null;
  }
}

class LoteTime extends HTMLElement {
  static get observedAttributes() {
    return ["datetime"];
  }

  #timeEl;

  constructor() {
    super();
    const shadow = this.attachShadow({ mode: "open" });
    const style = document.createElement("style");
    style.textContent = ":host { display: inline; } time { font: inherit; color: inherit; }";
    this.#timeEl = document.createElement("time");
    shadow.append(style, this.#timeEl);
  }

  connectedCallback() {
    instances.add(this);
    startTicker();
    this.render();
  }

  disconnectedCallback() {
    instances.delete(this);
    stopTickerIfIdle();
  }

  attributeChangedCallback() {
    this.render();
  }

  render(now = new Date()) {
    const iso = this.getAttribute("datetime");
    if (!iso) return;
    const date = new Date(iso);
    if (Number.isNaN(date.getTime())) return;

    const { text, title } = formatPostTimestamp(date, now);
    this.#timeEl.setAttribute("datetime", iso);
    this.#timeEl.setAttribute("title", title);
    this.#timeEl.textContent = text;
  }
}

if (!customElements.get("lote-time")) {
  customElements.define("lote-time", LoteTime);
}
