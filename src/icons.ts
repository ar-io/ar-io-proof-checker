// Inline SVG icons sourced from Lucide (https://lucide.dev, MIT license).
// Embedded as markup strings to avoid a runtime dependency. Each function
// returns an SVG element sized to fit inline with text (1em square).

function svg(paths: string, cls = ""): SVGElement {
  const el = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  el.setAttribute("width", "1em");
  el.setAttribute("height", "1em");
  el.setAttribute("viewBox", "0 0 24 24");
  el.setAttribute("fill", "none");
  el.setAttribute("stroke", "currentColor");
  el.setAttribute("stroke-width", "2.5");
  el.setAttribute("stroke-linecap", "round");
  el.setAttribute("stroke-linejoin", "round");
  if (cls) el.setAttribute("class", cls);
  el.innerHTML = paths;
  return el;
}

// Lucide: circle-check
export function iconCheckCircle(cls = ""): SVGElement {
  return svg('<circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/>', cls);
}

// Lucide: check
export function iconCheck(cls = ""): SVGElement {
  return svg('<path d="M20 6 9 17l-5-5"/>', cls);
}

// Lucide: triangle-alert
export function iconAlertTriangle(cls = ""): SVGElement {
  return svg(
    '<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3"/><path d="M12 9v4"/><path d="M12 17h.01"/>',
    cls,
  );
}

// Lucide: x-circle
export function iconXCircle(cls = ""): SVGElement {
  return svg('<circle cx="12" cy="12" r="10"/><path d="m15 9-6 6"/><path d="m9 9 6 6"/>', cls);
}

// Lucide: circle-alert
export function iconAlertCircle(cls = ""): SVGElement {
  return svg('<circle cx="12" cy="12" r="10"/><line x1="12" x2="12" y1="8" y2="12"/><line x1="12" x2="12.01" y1="16" y2="16"/>', cls);
}

// Lucide: shield-check
export function iconShieldCheck(cls = ""): SVGElement {
  return svg(
    '<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="m9 12 2 2 4-4"/>',
    cls,
  );
}

// Lucide: link
export function iconLink(cls = ""): SVGElement {
  return svg(
    '<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>',
    cls,
  );
}

// Lucide: unlink
export function iconUnlink(cls = ""): SVGElement {
  return svg(
    '<path d="m18.84 12.25 1.72-1.71h-.02a5.004 5.004 0 0 0-.12-7.07 5.006 5.006 0 0 0-6.95 0l-1.72 1.71"/><path d="m5.17 11.75-1.71 1.71a5 5 0 0 0 7.07 7.07l1.71-1.71"/><line x1="8" x2="8" y1="2" y2="5"/><line x1="2" x2="5" y1="8" y2="8"/><line x1="16" x2="16" y1="19" y2="22"/><line x1="19" x2="22" y1="16" y2="16"/>',
    cls,
  );
}
