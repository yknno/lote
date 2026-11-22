class LoteSentinel extends HTMLElement {
  static get observedAttributes() {
    return ["cursor", "disabled"];
  }

  #observer = null;
  #lastEmittedCursor = null;

  connectedCallback() {
    this.#setupObserver();
  }

  disconnectedCallback() {
    this.#teardownObserver();
    this.#lastEmittedCursor = null;
  }

  attributeChangedCallback(name, oldValue, newValue) {
    if (oldValue === newValue) return;
    if (name === "cursor") {
      this.#lastEmittedCursor = null;
    }
    if (!this.isConnected) return;
    if (name === "cursor" || name === "disabled") {
      this.#teardownObserver();
      this.#setupObserver();
    }
  }

  #teardownObserver() {
    if (this.#observer) {
      this.#observer.disconnect();
      this.#observer = null;
    }
  }

  #setupObserver() {
    if (this.hasAttribute("disabled")) return;
    if (typeof IntersectionObserver !== "function") return;

    const cursor = this.getAttribute("cursor") || "";
    this.#observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (!entry.isIntersecting) continue;
          if (this.hasAttribute("disabled")) return;
          if (this.#lastEmittedCursor === cursor && cursor !== "") return;
          this.#lastEmittedCursor = cursor;
          this.dispatchEvent(new CustomEvent("load-more"));
          return;
        }
      },
      { rootMargin: "200px 0px" },
    );
    this.#observer.observe(this);
  }
}

if (!customElements.get("lote-sentinel")) {
  customElements.define("lote-sentinel", LoteSentinel);
}
