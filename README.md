# Linux Authentication Log Triage

Extracts successful and failed OpenSSH logins from a saved `auth.log` sample and summarizes failure counts by source IP.

```bash
python main.py sample_auth.log
python -m unittest -v
```

The sample uses documentation-only IP ranges. Detection output is an investigation starting point, not a final attribution.
