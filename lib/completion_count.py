"""Record count for the job-completion debug line (#1992).

Tools return `{'success': bool, 'output': {...}}`; the record list lives
under `output` and is named `findings` (ASM/DAST), `items` (DRP mention
collectors) or `results` (some scanners). The count must unwrap the envelope
and name the key it counted so a sweep that found 40 mentions never prints
`Findings count: 0`.
"""
from typing import Any

RECORD_KEYS = ('findings', 'items', 'results')


def describe_record_count(output: Any) -> str:
    if not isinstance(output, dict):
        return 'N/A'
    inner = output.get('output')
    for candidate in ((inner if isinstance(inner, dict) else None), output):
        if candidate is None:
            continue
        for key in RECORD_KEYS:
            value = candidate.get(key)
            if isinstance(value, list):
                return f"{len(value)} ({key})"
    return '0 (no findings/items/results list)'
