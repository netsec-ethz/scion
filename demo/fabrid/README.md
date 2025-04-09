# FABRID demo

This demo shows how a SCION endhost can use FABRID to communicate with another SCION endhost
residing in another AS.

The demo consists of the following steps:

1. Enable and configure FABRID and start the topology.
2. Start a SCION endhost acting as a server in one AS and starting a SCION endhost acting as
a client in another AS
3. The client fetches a FABRID enabled path to the destination endhost and requests the
necessary key material
4. The client sends 10 times a FABRID packet to the destination endhost and the destination
endhost will respond to each packet

## Run the demo

1. [Set up the development environment](https://docs.scion.org/en/latest/build/setup.html)
2. `bazel test --test_output=streamed --cache_test_results=no //demo/fabrid:test`

Note: this demo works on any SCION network topology. To run the demo on a
different network topology, modify the `topo` parameter in `BUILD.bazel` to
point to a different topology file.
