  import { describe, it } from "node:test";
import assert from "node:assert/strict";

// These tests cover the documented heuristic patterns, not overall security.
function classify(text) {
  const value = text.toLowerCase();
  const patterns = [
    { name: "prompt injection", regex: /ignore (all )?(previous|prior|above) instructions|system prompt|jailbreak/, weight: 40 },
    { name: "data disclosure", regex: /api keys?|passwords?|private customer|credentials|personal data/, weight: 35 },
    { name: "dangerous action", regex: /delete (all|the|every)|transfer funds|bypass (security|approval|permission)|disable (logging|security)/, weight: 30 },
    { name: "suspicious destination", regex: /attacker@|external website|public chat/, weight: 15 }
