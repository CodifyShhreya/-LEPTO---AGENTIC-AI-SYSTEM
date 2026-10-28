import { NextRequest, NextResponse } from "next/server";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type Risk = "low" | "medium" | "high";
type PolicyInput = { id?: string; enabled?: boolean };

function analyze(text: string, policies: PolicyInput[]) {
  const value = text.toLowerCase();
  const rules: Array<{ id: string; name: string; patterns: RegExp[]; weight: number }> = [
    { id: "prompt-injection", name: "Instruction override / prompt injection", patterns: [/ignore (all )?(previous|prior|above) instructions/, /disregard (all )?(previous|prior|system)/, /system prompt/, /developer message/, /jailbreak/, /act as an unrestricted/, /reveal .* instructions/], weight: 40 },
    { id: "data-exfiltration", name: "Sensitive data disclosure", patterns: [/api keys?/, /passwords?/, /private customer/, /personal data/, /secret(s)?/, /send .* (outside|externally|attacker)/, /exfiltrat/, /export .* records/, /credentials/], weight: 35 },
    { id: "dangerous-actions", name: "Potentially unauthorized tool action", patterns: [/delete (all|the|every)/, /transfer funds/, /send .* email/, /execute (this|the) command/, /bypass (security|approval|permission)/, /disable (logging|security)/, /without asking for approval/], weight: 30 },
    { id: "untrusted-destination", name: "Suspicious destination", patterns: [/attacker@/, /unknown url/, /external website/, /public chat/, /external recipient/], weight: 15 }
  ];
  const active = rules.filter((rule) => !policies.some((p) => p.id === rule.id) || policies.some((p) => p.id === rule.id && p.enabled !== false));
  const threats = active.filter((rule) => rule.patterns.some((pattern) => pattern.test(value)));
  const score = Math.min(99, threats.reduce((sum, rule) => sum + rule.weight, 0));
  const riskLevel: Risk = score >= 60 ? "high" : score >= 25 ? "medium" : "low";
  return {
    riskLevel,
    score,
    threats: threats.map((rule) => rule.name),
    executionAllowed: riskLevel === "low",
    recommendation: riskLevel === "high"
      ? "Block the proposed action and require human review. Verify against an independent policy engine."
      : riskLevel === "medium"
      ? "Pause execution and verify intent, data scope, destination, and permissions."
      : "No configured pattern matched. Still enforce authorization and validate tool inputs.",
    summary: riskLevel === "low"
      ? "No configured high-risk pattern matched. This does not prove the request is safe."
      : "Potentially unsafe behavior was detected. Do not rely on this prototype as the sole security control."
  };
}

export async function POST(request: NextRequest) {
  try {
    const body: unknown = await request.json();
    if (!body || typeof body !== "object" || !("text" in body) || typeof body.text !== "string") {
      return NextResponse.json({ error: "Expected a JSON body with a text string." }, { status: 400 });
    }
    const text = body.text.trim();
    if (!text) return NextResponse.json({ error: "Text cannot be empty." }, { status: 400 });
    if (text.length > 12000) return NextResponse.json({ error: "Text exceeds the 12,000 character limit." }, { status: 413 });
    const policies = "policies" in body && Array.isArray(body.policies) ? body.policies as PolicyInput[] : [];
    const result = analyze(text, policies);
    return NextResponse.json(result, { headers: { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" } });
  } catch {
    return NextResponse.json({ error: "Invalid JSON request." }, { status: 400, headers: { "Cache-Control": "no-store" } });
  }
}
