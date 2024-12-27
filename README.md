# flake8-cq

Action to integrate Flake8 output into GitHub's Code Scanning Dashboard.

## Features

- Runs Flake8 linter on your Python codebase.
- Integrates Flake8 output directly into GitHub's Code Scanning Dashboard.
- Provides clear and actionable code quality reports.

## Installation

To use the `flake8-cq` action, you need to include it in your GitHub Actions workflow.

## Usage

Here is an example of how to use the `flake8-cq` action in your GitHub Actions workflow.

```yaml
name: Code Quality

on: [push, pull_request]
```

## Configuration

### inputs:

  * `path`
  * `match-pattern`
  * etc. (**TODO**)

## License

This repository is licensed under the MIT License. See the [LICENSE](./LICENSE) file for more
details.
