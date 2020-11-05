# SCION

[![SCIONLabDocs](https://img.shields.io/badge/docs-SCIONLab-blue)](https://docs.scionlab.org)
[![Documentation](https://img.shields.io/badge/go.dev-reference-007d9c?logo=go&logoColor=white)](https://pkg.go.dev/github.com/scionproto/scion)
[![ReadTheDocs](https://img.shields.io/badge/doc-reference-blue?version=latest&style=flat&label=docs&logo=read-the-docs&logoColor=white)](https://anapaya-scion.readthedocs-hosted.com/en/latest)
[![Go Report Card](https://goreportcard.com/badge/github.com/netsec-ethz/scion)](https://goreportcard.com/report/github.com/netsec-ethz/scion)
[![License](https://img.shields.io/github/license/netsec-ethz/scion.svg?maxAge=2592000)](https://github.com/netsec-ethz/scion/blob/scionlab/LICENSE)

Welcome to the open-source implementation of
[SCION](http://www.scion-architecture.net) (Scalability, Control and Isolation
On next-generation Networks), a future Internet architecture. SCION is the first
clean-slate Internet architecture designed to provide route control, failure
isolation, and explicit trust information for end-to-end communication. To find
out more about the project, please visit our [documentation
site](https://anapaya-scion.readthedocs-hosted.com/en/latest/).

## SCIONLab / this fork

Join [SCIONLab](https://www.scionlab.org) if you're interested in playing with
SCION in an operational global test deployment of SCION.

This fork of [scionproto/scion](github.com/scionproto/scion), specifically the
branch `scionlab`, is the version of SCION running in
[SCIONLab](https://www.scionlab.org).
Our version moves in a roughly biannual release cycle behind the upstream
master, which is an attempt to find a balance between the cutting edge and
periods of protocol and API stability. 
We typically maintain a few SCIONLab specific quirks here. Occasionally, we
include an experimental feature before it becomes available upstream.

## Building / Contributing

As part of the SCIONLab
project, we support [pre-built binaries as Debian
packages](https://docs.scionlab.org/content/install/).

Please contribute directly upsteam at [scionproto/scion](github.com/scionproto/scion) 
when possible; have a look at the 
[setup instructions](https://anapaya-scion.readthedocs-hosted.com/en/latest/build/setup.html)
and the [contribution guide](https://anapaya-scion.readthedocs-hosted.com/en/latest/contribute.html).

## License

[![License](https://img.shields.io/github/license/netsec-ethz/scion.svg?maxAge=2592000)](https://github.com/netsec-ethz/scion/blob/scionlab/LICENSE)
