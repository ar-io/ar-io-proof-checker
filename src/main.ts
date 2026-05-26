// Entry point. Wires the drop zone / file picker / gateway field to the
// provenance check and renders the result. Everything runs in the browser; no
// network call is made until the user supplies a file.

import { checkProvenance } from "./provenance";
import { DEFAULT_GATEWAY } from "./gateway";
import { renderReport } from "./render";
import "./styles.css";

const dropzone = byId("dropzone");
const fileInput = byId<HTMLInputElement>("file-input");
const gatewayInput = byId<HTMLInputElement>("gateway");
const results = byId("results");

gatewayInput.value = DEFAULT_GATEWAY;
gatewayInput.placeholder = DEFAULT_GATEWAY;

dropzone.addEventListener("click", () => fileInput.click());
fileInput.addEventListener("change", () => {
  const file = fileInput.files?.[0];
  if (file) void run(file);
});

dropzone.addEventListener("dragover", (e) => {
  e.preventDefault();
  dropzone.classList.add("dragging");
});
dropzone.addEventListener("dragleave", () => dropzone.classList.remove("dragging"));
dropzone.addEventListener("drop", (e) => {
  e.preventDefault();
  dropzone.classList.remove("dragging");
  const file = e.dataTransfer?.files?.[0];
  if (file) void run(file);
});

async function run(file: File): Promise<void> {
  const gateway = gatewayInput.value.trim() || DEFAULT_GATEWAY;
  results.replaceChildren(loading(file.name));
  try {
    const report = await checkProvenance(file, gateway);
    results.replaceChildren(renderReport(report));
  } catch (e) {
    // checkProvenance handles its own errors into a report; this only fires on
    // an unexpected fault (e.g. hashing). Surface it rather than swallowing.
    const box = document.createElement("div");
    box.className = "explain";
    box.textContent = `Unexpected error: ${e instanceof Error ? e.message : String(e)}`;
    results.replaceChildren(box);
  }
}

function loading(filename: string): HTMLElement {
  const box = document.createElement("div");
  box.className = "loading";
  box.textContent = `Hashing "${filename}" in your browser and querying the gateway…`;
  return box;
}

function byId<T extends HTMLElement = HTMLElement>(id: string): T {
  const node = document.getElementById(id);
  if (!node) throw new Error(`missing #${id} in document`);
  return node as T;
}
