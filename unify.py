#!/usr/bin/env python3
"""Merge three collectors' error event logs into one incident ledger.

Usage:
    python3 unify.py [data_dir]

Reads src1.jsonl, src2.jsonl, src3.jsonl from data_dir (default: current
directory) and writes incidents.csv, offsets.txt, missing.txt there.
"""
import collections
import csv
import datetime as dt
import json
import os
import sys

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
WINDOW = 300.0        # adjacency window width, seconds (5 minutes)
REOPEN_GAP = 3600.0   # gap larger than this after an instance ends -> reopen
DUP_TOLERANCE = 1.0   # rows this close are the same occurrence seen by peers
UTC = dt.timezone.utc


# ---------------------------------------------------------------------------
# Per-source parsing
# ---------------------------------------------------------------------------
def parse_iso(text):
    """ISO8601 without timezone -> UTC epoch seconds."""
    stamp = dt.datetime.fromisoformat(text)
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=UTC)
    return stamp.timestamp()


# time field, level field, level mapping, time converter
ADAPTERS = {
    "src1": ("ts", "lvl", {"ERROR": "ERROR", "WARN": "WARN", "INFO": "INFO"},
             lambda v: v / 1000.0),
    "src2": ("time", "level", {"E": "ERROR", "W": "WARN", "I": "INFO"},
             parse_iso),
    "src3": ("t", "sev", {3: "ERROR", 2: "WARN", 1: "INFO"},
             lambda v: float(v)),
}


def load_events(path, src):
    """Return (events, missing_count).

    events: list of (raw_ts_seconds, level, fingerprint, src_name)
    Only rows carrying a non-empty fingerprint are returned; rows without one
    are counted and left out of the merge.
    """
    time_key, level_key, level_map, convert = ADAPTERS[src]
    events = []
    missing = 0
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            stack = row.get("stack")
            if stack is None or str(stack).strip() == "":
                missing += 1
                continue
            events.append((convert(row[time_key]),
                           level_map[row[level_key]],
                           str(stack), src))
    return events, missing


# ---------------------------------------------------------------------------
# Clock-offset inference
# ---------------------------------------------------------------------------
def group_times(events):
    """(level, fingerprint) -> sorted list of raw timestamps."""
    grouped = collections.defaultdict(list)
    for t, level, stack, _src in events:
        grouped[(level, stack)].append(t)
    for times in grouped.values():
        times.sort()
    return grouped


def estimate_offset(ref_grouped, group, max_lag=3600.0):
    """Offset (this source's clock minus reference clock), seconds.

    Every occurrence of a fault can be caught by several collectors, all
    timestamping it with their own skewed clock.  For each same-level,
    same-fingerprint group the two sources share, every pair of events within
    max_lag seconds votes on the difference between their clocks.  The clock
    error is constant, so the true difference collects a large peak while
    pairings of unrelated events only add noise.  The peak is located coarsely
    first, then refined to sub-second precision by a median over its
    neighbourhood.
    """
    votes = collections.Counter()
    raw = []
    for key, times in group.items():
        ref_times = ref_grouped.get(key)
        if not ref_times:
            continue
        for t in times:
            for r in ref_times:
                d = t - r
                if abs(d) <= max_lag:
                    votes[round(d / 5.0) * 5.0] += 1     # 5 s coarse bins
                    raw.append(d)
    if not votes:
        return 0.0
    coarse = votes.most_common(1)[0][0]
    near = [d for d in raw if abs(d - coarse) <= 5.0]
    if not near:
        return float(coarse)
    # Among the near candidates the true offset repeats most often; a median
    # backs that up when the clock resolution leaves several values tied.
    tally = collections.Counter(near)
    best, best_n = tally.most_common(1)[0]
    if list(tally.values()).count(best_n) > 1:
        near.sort()
        best = near[len(near) // 2]
    # Snap to whole seconds when the estimate is effectively integral.
    return float(round(best)) if abs(best - round(best)) < 0.05 else round(best, 3)


# ---------------------------------------------------------------------------
# Instance assembly
# ---------------------------------------------------------------------------
def chain_events(items):
    """Split one group's sorted (ts, src) events into candidate instances.

    Events less than one window apart are neighbours.  A gap of exactly the
    window width leaves the two windows merely touching; such events are
    arbitrated by split_by_centers().
    """
    instances = [[items[0]]]
    for item in items[1:]:
        if item[0] - instances[-1][-1][0] >= WINDOW:
            instances.append([item])
        else:
            instances[-1].append(item)
    return instances


def split_by_centers(instances):
    """Reassign events at a window junction to the nearer window center.

    Each window's representative moment is the midpoint between its first and
    last event; an event sitting where two windows touch belongs to whichever
    center is closer.  Repeats until membership is stable so the centers
    reflect the final membership.
    """
    for _ in range(20):
        centers = [(inst[0][0] + inst[-1][0]) / 2.0 for inst in instances]
        new = [[] for _ in instances]
        for inst in instances:
            for item in inst:
                best = min(range(len(instances)),
                           key=lambda j: (abs(item[0] - centers[j]), j))
                new[best].append(item)
        new = [inst for inst in new if inst]
        if new == instances:
            return instances
        instances = new
    return instances


def collapse(items):
    """Fold one group's rows into distinct fault occurrences.

    The same fault is often recorded by two or three collectors at once.  Once
    the clocks are aligned those duplicate reports land on the same instant
    (the logs resolve to a second), so rows closer together than
    DUP_TOLERANCE were produced by different collectors watching the same
    occurrence.  Returns one (time, sources) per occurrence, where sources is
    the set of collectors that reported it.
    """
    occurrences = []
    for t, src in items:
        last = occurrences[-1] if occurrences else None
        if last and t - last[0] <= DUP_TOLERANCE and src not in last[1]:
            last[1].add(src)
        else:
            occurrences.append((t, {src}))
    return occurrences


def iso_seconds(ts):
    return dt.datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%S")


def num(value):
    """Render a number without a trailing .0 when integral."""
    if abs(value - round(value)) < 1e-9:
        return str(int(round(value)))
    return ("%.3f" % value).rstrip("0").rstrip(".")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    data_dir = sys.argv[1] if len(sys.argv) > 1 else "."

    events = []
    missing_total = 0
    by_src = {}
    for src in ("src1", "src2", "src3"):
        src_events, missing = load_events(os.path.join(data_dir, src + ".jsonl"), src)
        by_src[src] = src_events
        events.extend(src_events)
        missing_total += missing

    # Clock offsets relative to src1 (positive = that clock runs fast).
    ref_grouped = group_times(by_src["src1"])
    offsets = {"src1": 0.0}
    for src in ("src2", "src3"):
        offsets[src] = estimate_offset(ref_grouped, group_times(by_src[src]))

    # A fault occurrence is frequently captured by two or three collectors at
    # once; those rows describe one event, not two or three.  Once the clocks
    # are on the shared timeline the copies coincide, so duplicates are folded
    # per level+fingerprint group before the instances are assembled.
    normalized = [(t - offsets[src], level, stack, src)
                  for t, level, stack, src in events]

    grouped = collections.defaultdict(list)
    for t, level, stack, src in normalized:
        grouped[(level, stack)].append((t, src))
    for items in grouped.values():
        items.sort()

    rows = []
    for (level, stack), items in grouped.items():
        occurrences = collapse(items)
        instances = split_by_centers(chain_events(occurrences))

        reopen = 0
        prev_last = None
        for inst in instances:
            if prev_last is not None and inst[0][0] - prev_last > REOPEN_GAP:
                reopen += 1
            sources = sorted({int(src[3:]) for _t, peers in inst for src in peers})
            rows.append({
                "first_ts": iso_seconds(inst[0][0]),
                "last_ts": iso_seconds(inst[-1][0]),
                "level": level,
                "hits": len(inst),
                "sources": ";".join(str(s) for s in sources),
                "reopen_cnt": reopen,
            })
            prev_last = inst[-1][0]

    rows.sort(key=lambda r: (r["first_ts"], r["last_ts"], r["level"], r["sources"]))

    out_csv = os.path.join(data_dir, "incidents.csv")
    with open(out_csv, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["first_ts", "last_ts", "level",
                                                "hits", "sources", "reopen_cnt"])
        writer.writeheader()
        writer.writerows(rows)

    with open(os.path.join(data_dir, "offsets.txt"), "w", encoding="utf-8") as fh:
        for src in ("src1", "src2", "src3"):
            fh.write("%s %s\n" % (src, num(offsets[src])))

    with open(os.path.join(data_dir, "missing.txt"), "w", encoding="utf-8") as fh:
        fh.write("%d\n" % missing_total)

    print("events merged: %d, instances: %d, missing fingerprint rows: %d"
          % (len(events), len(rows), missing_total), file=sys.stderr)
    print("offsets: " + ", ".join("%s=%s" % (s, num(offsets[s]))
                                  for s in ("src1", "src2", "src3")),
          file=sys.stderr)


if __name__ == "__main__":
    main()
