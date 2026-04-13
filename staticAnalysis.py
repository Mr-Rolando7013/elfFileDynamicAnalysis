import re
import subprocess
import json
from collections import defaultdict

# -----------------------------
# Regex patterns (for instructions)
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
# JSON helpers
# -----------------------------

def run_bpftool_json(cmd):
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True
    )

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return None

# -----------------------------
# Get all programs (JSON)
# -----------------------------

def get_all_programs():
    data = run_bpftool_json(["bpftool", "-j", "prog", "list"])
    if not data:
        return []

    programs = []

    for prog in data:
        programs.append({
            "id": prog.get("id"),
            "type": prog.get("type"),
            "name": prog.get("name"),
            "tag": prog.get("tag")
        })

    return programs

# -----------------------------
# Get program context (JSON)
# -----------------------------

def get_prog_context(prog_id):
    data = run_bpftool_json(["bpftool", "-j", "prog", "show", "id", str(prog_id)])

    if not data:
        return {"type": None, "name": None}

    # 🔥 FIX: handle both dict and list
    if isinstance(data, list):
        prog = data[0]
    elif isinstance(data, dict):
        prog = data
    else:
        return {"type": None, "name": None}

    return {
        "type": prog.get("type"),
        "name": prog.get("name"),
        "attach_type": prog.get("attach_type"),
        "attach_func": prog.get("attach_func")
    }
# -----------------------------
# Dump instructions (text)
# -----------------------------

def dump_prog_instructions(prog_id):
    result = subprocess.run(
        ["bpftool", "prog", "dump", "xlated", "id", str(prog_id)],
        capture_output=True,
        text=True
    )

    return result.stdout.splitlines()

# -----------------------------
# Hook classification
# -----------------------------

def classify_hook(ctx):
    name = (ctx.get("name") or "").lower()
    attach_func = (ctx.get("attach_func") or "").lower()

    combined = name + " " + attach_func

    if "getdents" in combined:
        return "filesystem_listing"

    if any(x in combined for x in ["tcp", "udp", "recvmsg", "sendmsg"]):
        return "network_io"

    if "execve" in combined:
        return "process_execution"

    if "open" in combined:
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

def analyze_lines(lines):
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
# Behavior inference
# -----------------------------

def infer_behavior(signal_counts, hook_type):

    if hook_type == "filesystem_listing":
        if signal_counts.get("selective_filtering", 0) > 0:
            if signal_counts.get("kernel_data_modification", 0) > 0:
                return "LIKELY_ROOTKIT_FILE_HIDING"

    if (
        signal_counts.get("selective_filtering", 0) > 0 and
        signal_counts.get("kernel_data_modification", 0) > 0
    ):
        return "possible_stealth_modification"

    if signal_counts.get("syscall_inspection", 0) > 0:
        return "likely_observability"

    return "unknown"

# -----------------------------
# Risk scoring
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
# Summary builder
# -----------------------------

def build_summary(graph, ctx):
    signal_counts = extract_signal_counts(graph)

    hook_type = classify_hook(ctx)

    behavior = infer_behavior(signal_counts, hook_type)

    risk_score, findings, _ = contextual_risk(graph, ctx)

    return {
        "hook_name": ctx.get("name"),
        "hook_type": hook_type,
        "program_type": ctx.get("type"),
        "attach_func": ctx.get("attach_func"),

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

# -----------------------------
# Cross-program correlation
# -----------------------------

def correlate_programs(programs):
    patterns = []

    hooks = [p["summary"]["hook_name"] or "" for p in programs]
    types = [p["summary"]["program_type"] for p in programs]

    if any("getdents" in h for h in hooks):
        if "xdp" in types:
            patterns.append("filesystem_hiding + network_component")

    return patterns

# -----------------------------
# MAIN
# -----------------------------

if __name__ == "__main__":
    programs_meta = get_all_programs()

    print(f"[+] Found {len(programs_meta)} eBPF programs")

    analyzed_programs = []

    for prog in programs_meta:
        prog_id = prog["id"]

        print(f"\n[+] Analyzing program ID: {prog_id}")

        ctx = get_prog_context(prog_id)

        lines = dump_prog_instructions(prog_id)
        if not lines:
            continue

        graph = analyze_lines(lines)

        summary = build_summary(graph, ctx)

        analyzed_programs.append({
            "id": prog_id,
            "context": ctx,
            "summary": summary
        })

        print(summary)

    print("\n=== CROSS PROGRAM ANALYSIS ===")

    patterns = correlate_programs(analyzed_programs)

    for p in patterns:
        print("[!] Detected pattern:", p)