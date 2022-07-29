# Galadriel

[![CodeQL](https://github.com/HewlettPackard/Galadriel/actions/workflows/codeql.yml/badge.svg)](https://github.com/HewlettPackard/Galadriel/actions/workflows/codeql.yml)
[![PR Build](https://github.com/HewlettPackard/Galadriel/actions/workflows/linter.yml/badge.svg)](https://github.com/HewlettPackard/Galadriel/actions/workflows/linter.yml)
[![Scorecards supply-chain security](https://github.com/HewlettPackard/Galadriel/actions/workflows/scorecards.yml/badge.svg)](https://github.com/HewlettPackard/Galadriel/actions/workflows/scorecards.yml)
[![trivy](https://github.com/HewlettPackard/Galadriel/actions/workflows/trivy.yml/badge.svg)](https://github.com/HewlettPackard/Galadriel/actions/workflows/trivy.yml)

## Development

### REST API

Server and Client Go code is generated from the OpenAPI definition by [oapi-codegen](https://github.com/deepmap/oapi-codegen).

To generate the OpenAPI code:

`make generate-oapi`

### API view

To visualize a live view of the API documentation:

```bash
make api-doc
```
This command will generate and serve simple web pages based off `api.yaml` to facilitate exploring and testing the API. 
Further changes in your API definition file can be reloaded by refreshing the website (a hard-refresh may be required to
avoid caching issues). This service will be available at `http://localhost:8000`.

### Testing

There are a few make targets available to test the code:

* `make test`: Runs all tests.
* `make coverage`: Runs all unit tests and reports back test coverage. More details can be found in the file `./out/coverage/index.html`.
