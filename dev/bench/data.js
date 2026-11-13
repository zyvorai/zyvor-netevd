window.BENCHMARK_DATA = {
  "lastUpdate": 1794588643262,
  "repoUrl": "https://github.com/zyvorai/zyvor-netevd",
  "entries": {
    "Rust Benchmarks": [
      {
        "commit": {
          "author": {
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "07267aacedf7b423e10fadd87a840ee906cba5b4",
          "message": "build(deps): Bump rtnetlink from 0.23.0 to 0.24.0 (#139)\n\nBumps [rtnetlink](https://github.com/rust-netlink/rtnetlink) from 0.23.0 to 0.24.0.\n- [Release notes](https://github.com/rust-netlink/rtnetlink/releases)\n- [Changelog](https://github.com/rust-netlink/rtnetlink/blob/main/CHANGELOG)\n- [Commits](https://github.com/rust-netlink/rtnetlink/compare/v0.23.0...v0.24.0)\n\n---\nupdated-dependencies:\n- dependency-name: rtnetlink\n  dependency-version: 0.24.0\n  dependency-type: direct:production\n  update-type: version-update:semver-minor\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>\nCo-authored-by: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>",
          "timestamp": "2026-11-13T21:46:02+05:30",
          "tree_id": "5c0ac68fd2499019f6d8a14e76a4a01e1ac21c22",
          "url": "https://github.com/zyvorai/zyvor-netevd/commit/07267aacedf7b423e10fadd87a840ee906cba5b4"
        },
        "date": 1794588642344,
        "tool": "cargo",
        "benches": [
          {
            "name": "validate_interface_name",
            "value": 3,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sanitize_env_value",
            "value": 18,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "interface_selector_allows",
            "value": 115566,
            "range": "± 5565",
            "unit": "ns/iter"
          },
          {
            "name": "hook_event_to_json",
            "value": 214,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "hook_event_to_env",
            "value": 471,
            "range": "± 16",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}