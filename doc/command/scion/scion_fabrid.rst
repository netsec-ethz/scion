:orphan:

.. _scion_fabrid:

scion fabrid
------------

Display FABRID policy information

Synopsis
~~~~~~~~


'fabrid' fetches the description of a global or local FABRID policy.

::

  scion fabrid identifier [remote_as] [flags]

Examples
~~~~~~~~

::

    scion fabrid G1001
    scion fabrid L1101 1-ff00:0:110
    scion fabrid L1101 1-ff00:0:110 --log.level debug'

Options
~~~~~~~

::

      --format string          Specify the output format (human|json|yaml) (default "human")
  -h, --help                   help for fabrid
      --isd-as isd-as          The local ISD-AS to use. (default 0-0)
  -l, --local ip               Local IP address to listen on. (default invalid IP)
      --log.level string       Console logging level verbosity (debug|info|error)
      --no-color               disable colored output
      --sciond string          SCION Daemon address. (default "127.0.0.1:30255")
      --timeout duration       Timeout (default 5s)
      --tracing.agent string   Tracing agent address

SEE ALSO
~~~~~~~~

* :ref:`scion <scion>` 	 - SCION networking utilities.

