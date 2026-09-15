# Defensive Security Portfolio

Three reproducible, offline learning projects for entry-level SOC and cybersecurity practice. Created with AI assistance; synthetic fixtures and generated outputs are labelled explicitly. These projects are learning materials, not evidence of employment or completed investigations against real systems.

| Project | Skill | Evidence |
|---|---|---|
| [Authentication triage](auth-triage/) | Python, time-window detection, investigation | Synthetic CSV and generated alert |
| [Nmap inventory](nmap-inventory/) | Network exposure interpretation | Synthetic XML and open-service inventory |
| [Header review](header-review/) | Web hardening and technical reporting | Synthetic headers and contextual findings |

## Requirements
Python 3.10 or later; no third-party dependencies. All commands run offline on Linux, Windows or macOS. On Windows, replace `python3` with `py` if needed.

## Test
```bash
cd portfolio
python3 -m unittest discover -s tests -v
```

## Learning sequence
Run each sample, compare it with expected.json, read the limitations, modify the fixture, and explain how the output changes. Use only authorized, sanitized real data if extending these labs. Do not publish credentials or private logs.
