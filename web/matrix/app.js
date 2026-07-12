"use strict";

const form = document.getElementById("filters");
const body = document.getElementById("observations");
const status = document.getElementById("status");
const more = document.getElementById("more");
let nextCursor = "";

function valueAt(object, path, fallback = "unknown") {
  let value = object;
  for (const key of path) {
    if (!value || typeof value !== "object" || !(key in value)) return fallback;
    value = value[key];
  }
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") return String(value);
  return fallback;
}

function listAt(object, path, fallback = "unknown") {
  let value = object;
  for (const key of path) {
    if (!value || typeof value !== "object" || !(key in value)) return fallback;
    value = value[key];
  }
  if (!Array.isArray(value) || value.length === 0 || value.some((item) => typeof item !== "string")) return fallback;
  return value.join(", ");
}

function cell(row, value, className = "") {
  const item = document.createElement("td");
  item.textContent = value;
  if (className) item.className = className;
  row.appendChild(item);
}

function render(observation) {
  const row = document.createElement("tr");
  cell(row, `${valueAt(observation, ["subject", "project"])}@${valueAt(observation, ["subject", "version"])}`);
  cell(row, `${valueAt(observation, ["test", "pack"])}@${valueAt(observation, ["test", "pack_version"])}`);
  cell(row, valueAt(observation, ["test", "profile"]));
  const outcome = valueAt(observation, ["result", "profile_outcome"]);
  cell(row, outcome, `outcome outcome-${outcome.replace(/[^a-z_]/g, "")}`);
  cell(row, listAt(observation, ["registry_derived", "trust_labels"]));
  cell(row, valueAt(observation, ["registry_derived", "freshness"]));
  cell(row, valueAt(observation, ["observation_id"]), "digest");
  body.appendChild(row);
}

function parameters(cursor = "") {
  const query = new URLSearchParams();
  for (const [name, value] of new FormData(form).entries()) {
    const text = String(value).trim();
    if (text) query.set(name, text);
  }
  query.set("limit", "25");
  if (cursor) query.set("cursor", cursor);
  return query;
}

async function load(cursor = "") {
  status.textContent = "Loading observations…";
  more.disabled = true;
  try {
    const response = await fetch(`/v1/observations?${parameters(cursor)}`, {headers: {Accept: "application/json"}, credentials: "omit", redirect: "error"});
    if (!response.ok) throw new Error(`Registry returned HTTP ${response.status}`);
    const payload = await response.json();
    if (!payload || !Array.isArray(payload.items)) throw new Error("Registry returned an invalid list contract");
    if (!cursor) body.replaceChildren();
    for (const observation of payload.items) render(observation);
    nextCursor = typeof payload.next_cursor === "string" ? payload.next_cursor : "";
    more.hidden = !nextCursor;
    status.textContent = payload.items.length ? `Loaded ${payload.items.length} observation(s).` : "No observations match these exact filters.";
  } catch (error) {
    status.textContent = error instanceof Error ? error.message : "The Registry query failed.";
    nextCursor = "";
    more.hidden = true;
  } finally {
    more.disabled = false;
  }
}

form.addEventListener("submit", (event) => { event.preventDefault(); load(); });
more.addEventListener("click", () => { if (nextCursor) load(nextCursor); });
load();
