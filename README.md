# flake8-cq

Action to integrate Flake8 output into GitHub's Code Scanning Dashboard.

## Features

 - Runs `Flake8` linter on your Python codebase.
 - Integrates `Flake8` output directly into GitHub's Code Scanning Dashboard.
 - Provides clear and actionable code quality reports.

## Requirements

 - GitHub repository with Python code
 - GitHub Actions enabled

## Installation

To use the `flake8-cq` action, you need to include it in your GitHub Actions workflow.

## Usage

Here is an example of how to use the `flake8-cq` action in your GitHub Actions workflow.

```yaml
name: Code Quality

on: [push, pull_request]

jobs:
  flake8-lint:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v5

      - name: Run flake8-cq
        uses: reactive-firewall/flake8-cq@master
        with:
          path: "src/"
          match: "*.py"
```

## Configuration

### inputs

  * `config`: The file or _glob_ to slurp up `flake8` configuration from. **Default** is `UNDEFINED`.
  * `path`: The path to the directory containing your Python code.
    **Default** is to use `git` to `match` paths.
  * `match`: The glob pattern to match Python files (e.g., `*.py`).
    Only works with `git` tracked files. _Overriden_ by setting a value for `path`.

> [!TIP]
> The `path` input can be used to scan files not traked by
> git (e.g. downloaded tools and build artifacts in the given `path`).

### Full Example

```yaml
name: Code Quality

# Triggers the workflow on push or pull request events, but only for changes in the specified paths
on:
  push:
    paths:
      - 'src/**'  # Path to the Python source files
      - '.flake8'  # Path to the Flake8 configuration file
  pull_request:
    paths:
      - 'src/**'  # Path to the Python source files
      - '.flake8'  # Path to the Flake8 configuration file

jobs:
  flake8-lint:
    permissions:
      contents: read  # used by actions/checkout and reactive-firewall/flake8-cq to scan your code.
      security-events: write  # used by reactive-firewall/flake8-cq to upload (via github/codeql-action/upload-sarif) the results to GitHub.
      statuses: write  # OPTIONAL used to update check-status on workflow re-runs
      pull-requests: read  # OPTIONAL used to read pull-request metadata
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v5

      - name: Run flake8-cq
        uses: reactive-firewall/flake8-cq@master
        with:
          config: ".flake8"  # Specify the Flake8 configuration file
          path: "src/"
          match: "*.py"

```

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.

## License

This repository is licensed under the MIT License. See the [LICENSE](./LICENSE) file for more
details.
