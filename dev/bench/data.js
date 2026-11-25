window.BENCHMARK_DATA = {
  "lastUpdate": 1795594304713,
  "repoUrl": "https://github.com/zyvorai/zyvor-netevd",
  "entries": {
    "Rust Benchmarks": [
      {
        "commit": {
          "author": {
            "email": "ssahani@gmail.com",
            "name": "Susant Sahani",
            "username": "ssahani"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "599ef4ced5f957de0871ade7839ad596c372d58a",
          "message": "feat: API TLS and token auth, health checks, hook trigger, script results; fix CI (#159)\n\nSecurity fix: api.tls was parsed and validated but ignored, so the API was\nserved as plain HTTP. It is now served over TLS, and is not started at all\nwhen configured TLS or token material cannot be loaded.\n\n- API bearer-token authentication; /health and /health/ready stay public\n- CLI: https endpoints, --ca-file, --token-file, truncated-response checks\n- Live /health, new /health/ready and `netevd health`\n- `netevd trigger`: run hook scripts for a synthetic or recorded event\n- Journal, events API and CLI record per-script results; a failing script\n  makes the dispatch \"failed\"; outcome filter\n- Script and daemon gauge metrics are now updated\n- Interfaces and routes API read real kernel data\n- Fix clashing short options in `netevd events` (-o format, -n tail)\n- Fix Kubernetes ConfigMap keys and probes\n- CI: container zombie test, functional test binary lookup, lychee install,\n  link-time memory\n- Dependencies: rustls, tokio-rustls, rustls-native-certs, ring, subtle,\n  rcgen (dev); cargo update\n\nCo-authored-by: Claude Sonnet 5.5 <noreply@anthropic.com>",
          "timestamp": "2026-11-25T13:33:14+05:30",
          "tree_id": "8d8f8b91d9097f9529e6b72b1a8879e97e4ce46b",
          "url": "https://github.com/zyvorai/zyvor-netevd/commit/599ef4ced5f957de0871ade7839ad596c372d58a"
        },
        "date": 1795594303312,
        "tool": "cargo",
        "benches": [
          {
            "name": "validate_interface_name",
            "value": 6,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sanitize_env_value",
            "value": 31,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "interface_selector_allows",
            "value": 162673,
            "range": "± 978",
            "unit": "ns/iter"
          },
          {
            "name": "hook_event_to_json",
            "value": 298,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "hook_event_to_env",
            "value": 742,
            "range": "± 4",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}