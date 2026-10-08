window.BENCHMARK_DATA = {
  "lastUpdate": 1791461458516,
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
          "id": "9c8847fae5f285cd9986bb5d6ba733f60a3f9b9d",
          "message": "build(deps): Bump libc from 0.2.189 to 0.2.190 (#114)\n\nBumps [libc](https://github.com/rust-lang/libc) from 0.2.189 to 0.2.190.\n- [Release notes](https://github.com/rust-lang/libc/releases)\n- [Changelog](https://github.com/rust-lang/libc/blob/0.2.190/CHANGELOG.md)\n- [Commits](https://github.com/rust-lang/libc/compare/0.2.189...0.2.190)\n\n---\nupdated-dependencies:\n- dependency-name: libc\n  dependency-version: 0.2.190\n  dependency-type: direct:production\n  update-type: version-update:semver-patch\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>\nCo-authored-by: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>",
          "timestamp": "2026-10-08T17:27:25+05:30",
          "tree_id": "f906551fb68d11e9e4998c402340a8cfba14ca7d",
          "url": "https://github.com/zyvorai/zyvor-netevd/commit/9c8847fae5f285cd9986bb5d6ba733f60a3f9b9d"
        },
        "date": 1791461457339,
        "tool": "cargo",
        "benches": [
          {
            "name": "validate_interface_name",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sanitize_env_value",
            "value": 32,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "interface_selector_allows",
            "value": 193900,
            "range": "± 722",
            "unit": "ns/iter"
          },
          {
            "name": "hook_event_to_json",
            "value": 349,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "hook_event_to_env",
            "value": 907,
            "range": "± 13",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}