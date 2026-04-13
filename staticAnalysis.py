import re
import subprocess
from collections import defaultdict

# -----------------------------
# Regex patterns
# -----------------------------

CALL_RE = re.compile(r'call\s+([a-zA-Z0-9_#]+)')
MAP_RE = re.compile(r'map\[id:(\d+)\]')
STACK_WRITE_RE = re.compile(r'\*\(.*?\)\s*\(r10')
STACK_READ_RE = re.compile(r'r\d+\s*=\s*\*\(.*r10')
CTX_READ_RE = re.compile(r'r\d+\s*=\s*\*\(.*r6')

# -----------------------------
# Hook behavior rules
# -----------------------------

HOOK_BEHAVIOR_RULES = {
    "filesystem_listing": {
        "suspicious": [
            "return_value_tampering",
            "selective_filtering",
            "kernel_data_modification"
        ],
        "expected": [
            "syscall_inspection"
        ]
    },
    "network_io": {
        "suspicious": [
            "selective_filtering",
            "kernel_data_modification"
        ]
    },
    "packet_processing": {
        "suspicious": [],
        "expected": [
            "selective_filtering"
        ]
    }
}

# -----------------------------
# Context extraction
# -----------------------------

def get_prog_context(prog_id):
    result = subprocess.run(
        ["bpftool", "prog", "show", "id", str(prog_id)],
        capture_output=True,
        text=True
    )

    output = result.stdout

    ctx = {
        "type": None,
        "name": None
    }

    if "xdp" in output:
        ctx["type"] = "xdp"
    elif "tracepoint" in output:
        ctx["type"] = "tracepoint"
    elif "kprobe" in output:
        ctx["type"] = "kprobe"

    name_match = re.search(r'name\s+([^\s]+)', output)
    if name_match:
        ctx["name"] = name_match.group(1)

    return ctx

# -----------------------------
# Hook classification
# -----------------------------

def classify_hook(ctx):
    name = ctx.get("name", "") or ""

    if "getdents" in name:
        return "filesystem_listing"

    if "tcp" in name or "udp" in name:
        return "network_io"

    if "execve" in name:
        return "process_execution"

    if "open" in name:
        return "file_access"

    if ctx.get("type") == "xdp":
        return "packet_processing"

    return "unknown"

# -----------------------------
# Signal detection
# -----------------------------

def detect_signals(inst, idx):
    signals = []

    if "bpf_get_current_pid_tgid" in inst:
        signals.append({"type": "process_tracking", "line": idx})

    if "map_update_elem" in inst:
        signals.append({"type": "stateful_tracking", "line": idx})

    if "ctx->args" in inst:
        signals.append({"type": "syscall_inspection", "line": idx})

    if "map_lookup_elem" in inst:
        signals.append({"type": "state_lookup", "line": idx})

    if re.search(r'if r\d+ .* goto', inst):
        signals.append({"type": "selective_filtering", "line": idx})

    if "*(u" in inst and "= r" in inst:
        signals.append({"type": "kernel_data_modification", "line": idx})

    if re.search(r'r0\s*=', inst):
        signals.append({"type": "return_value_tampering", "line": idx})

    return signals

# -----------------------------
# Instruction classification
# -----------------------------

def classify_instruction(inst, idx):
    node = {
        "line": idx,
        "raw": inst.strip(),
        "type": None,
        "details": {}
    }

    call = CALL_RE.search(inst)
    if call:
        node["type"] = "helper_call"
        node["details"]["helper"] = call.group(1)

    elif "map[" in inst:
        node["type"] = "map_access"
        m = MAP_RE.search(inst)
        if m:
            node["details"]["map_id"] = m.group(1)

    elif STACK_WRITE_RE.search(inst):
        node["type"] = "stack_write"

    elif STACK_READ_RE.search(inst):
        node["type"] = "stack_read"

    elif CTX_READ_RE.search(inst):
        node["type"] = "ctx_read"

    else:
        node["type"] = "alu_or_other"

    return node

# -----------------------------
# Analyzer
# -----------------------------

def analyze(filepath):
    with open(filepath, "r") as f:
        lines = f.readlines()

    nodes = []
    signals = []
    edges = []

    prev = None

    for idx, line in enumerate(lines):
        node = classify_instruction(line, idx)
        nodes.append(node)

        sigs = detect_signals(line, idx)
        signals.extend(sigs)

        if prev:
            edges.append((prev["line"], node["line"]))

        prev = node

    return {
        "nodes": nodes,
        "signals": signals,
        "edges": edges
    }

# -----------------------------
# Signal aggregation
# -----------------------------

def extract_signal_counts(graph):
    counts = defaultdict(int)
    for s in graph["signals"]:
        counts[s["type"]] += 1
    return dict(counts)

# -----------------------------
# Behavior inference (CONTEXT-AWARE)
# -----------------------------

def infer_behavior(signal_counts, hook_type):

    # 🔴 getdents rootkit pattern
    if hook_type == "filesystem_listing":
        if signal_counts.get("selective_filtering", 0) > 0:
            if signal_counts.get("kernel_data_modification", 0) > 0:
                return "LIKELY_ROOTKIT_FILE_HIDING"

    # 🟠 generic stealth modification
    if (
        signal_counts.get("selective_filtering", 0) > 0 and
        signal_counts.get("kernel_data_modification", 0) > 0
    ):
        return "possible_stealth_modification"

    # 🟡 normal tracing
    if signal_counts.get("syscall_inspection", 0) > 0:
        return "likely_observability"

    return "unknown"

# -----------------------------
# Contextual risk scoring
# -----------------------------

def contextual_risk(graph, ctx):
    hook_type = classify_hook(ctx)
    rules = HOOK_BEHAVIOR_RULES.get(hook_type, {})

    suspicious = rules.get("suspicious", [])
    expected = rules.get("expected", [])

    score = 0
    findings = []

    for s in graph["signals"]:
        t = s["type"]

        if t in suspicious:
            score += 1.0
            findings.append((t, "suspicious_in_this_hook"))

        elif t in expected:
            score += 0.1

        else:
            score += 0.3

    return score, findings, hook_type

# -----------------------------
# Final summary builder
# -----------------------------

def build_summary(graph, ctx):
    signal_counts = extract_signal_counts(graph)

    hook_type = classify_hook(ctx)

    behavior = infer_behavior(signal_counts, hook_type)

    risk_score, findings, _ = contextual_risk(graph, ctx)

    summary = {
        "hook_name": ctx.get("name"),
        "hook_type": hook_type,
        "program_type": ctx.get("type"),

        "total_instructions": len(graph["nodes"]),
        "signal_distribution": signal_counts,

        "unique_helpers": list({
            n["details"].get("helper")
            for n in graph["nodes"]
            if n["type"] == "helper_call"
        } - {None}),

        "behavior_hint": behavior,
        "risk_score": risk_score,
        "findings": findings
    }

    return summary

# -----------------------------
# Main
# -----------------------------

if __name__ == "__main__":
    prog_id = 123  # <-- CHANGE THIS

    ctx = get_prog_context(prog_id)

    graph = analyze("getdents_patch.txt")

    summary = build_summary(graph, ctx)

    print("\n=== CONTEXT ===")
    print(ctx)

    print("\n=== SIGNALS ===")
    for s in graph["signals"]:
        print(s)

    print("\n=== SUMMARY ===")
    print(summary)