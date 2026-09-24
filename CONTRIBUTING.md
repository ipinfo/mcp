# Contributing

Thanks for your interest in improving the IPinfo MCP Server. This document explains how to propose a change and what a change needs before it can be merged.

## Reporting bugs and requesting features

Open an issue on [GitHub Issues](https://github.com/ipinfo/mcp/issues). For bugs, include the server version, how you run it (hosted, `uvx`, Claude Desktop extension), the tool call that failed, and the response you got.

Security vulnerabilities must not be reported as public issues. Follow the [security policy](SECURITY.md) instead.

## Workflow

1. Fork the repository (or create a branch, if you have write access).
2. Make your change, following the requirements below.
3. Open a pull request against `main` describing what the change does and why.
4. Wait for CI to pass and for an approving review from a maintainer.

All changes go through pull requests; nobody pushes directly to `main`.

## Requirements for acceptable contributions

A pull request is merged only when:

- **Linting passes:** `uv run ruff check .` reports no errors. The rules are configured in `pyproject.toml` (line length 120).
- **Code is formatted:** `uv run ruff format .` produces no changes.
- **Type checking passes:** `uv run pyright` reports no errors. All code under `src/` is fully type-annotated.
- **Tests pass:** `uv run pytest` succeeds.
- **Changes are tested:** new tools, parameters, or behaviour changes come with unit tests under `tests/` (tool tests live in `tests/tools/`). Unit tests mock the IPinfo API and must not require a token.
- **Documentation is updated:** changes to tools, parameters, outputs, or configuration are reflected in the [README](README.md).
- **The pull request is reviewed:** at least one maintainer approves it.

CI (`.github/workflows/test.yml`) runs linting, type checking, and tests on every pull request. CodeQL analysis also runs on every pull request, and any security findings it reports need to be addressed.

See the [Development](README.md#development) section of the README for how to set up the project and run these checks locally.

## License

By contributing, you agree that your contributions are licensed under the [Apache License 2.0](LICENSE.txt), the same license as the project.
