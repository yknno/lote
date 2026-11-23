const segmenter =
  typeof Intl !== "undefined" && typeof Intl.Segmenter === "function"
    ? new Intl.Segmenter(undefined, { granularity: "grapheme" })
    : null;

export function countGraphemes(text) {
  if (!text) return 0;
  if (segmenter) {
    let count = 0;
    for (const _ of segmenter.segment(text)) {
      count += 1;
    }
    return count;
  }
  return Array.from(text).length;
}

class LoteComposer extends HTMLElement {
  static get observedAttributes() {
    return ["max"];
  }

  #onInput = () => {
    this.#sync();
  };

  #onSubmit = (event) => {
    const textarea = this.querySelector('textarea[name="body"]');
    if (!textarea) return;
    const count = countGraphemes(textarea.value.trim());
    if (count === 0 || count > this.#maxLength()) {
      event.preventDefault();
      event.stopImmediatePropagation();
      this.#sync();
    }
  };

  #form = null;

  connectedCallback() {
    this.addEventListener("input", this.#onInput);
    this.#form = this.closest("form");
    if (this.#form) {
      // Use capture phase so our guard runs before Lustre's bubble-phase submit listener.
      this.#form.addEventListener("submit", this.#onSubmit, { capture: true });
    }
    this.#sync();
  }

  disconnectedCallback() {
    this.removeEventListener("input", this.#onInput);
    if (this.#form) {
      this.#form.removeEventListener("submit", this.#onSubmit, {
        capture: true,
      });
      this.#form = null;
    }
  }

  attributeChangedCallback() {
    if (this.isConnected) {
      this.#sync();
    }
  }

  #maxLength() {
    const parsed = Number.parseInt(this.getAttribute("max") || "300", 10);
    return Number.isFinite(parsed) && parsed > 0 ? parsed : 300;
  }

  #sync() {
    const textarea = this.querySelector('textarea[name="body"]');
    const counter = this.querySelector("[data-char-counter]");
    const submit = this.querySelector('button[type="submit"]');
    if (!textarea) return;

    const max = this.#maxLength();
    const count = countGraphemes(textarea.value.trim());
    const isOver = count > max;
    const isNear = !isOver && count >= Math.max(0, max - 30);

    if (counter) {
      counter.textContent = `${count} / ${max}`;
      counter.dataset.state = isOver ? "over" : isNear ? "near" : "ok";
    }

    if (isOver) {
      textarea.setAttribute("aria-invalid", "true");
    } else {
      textarea.removeAttribute("aria-invalid");
    }

    if (submit) {
      submit.disabled = isOver;
    }
  }
}

if (!customElements.get("lote-composer")) {
  customElements.define("lote-composer", LoteComposer);
}
