@0xf85d2602085656c1;

using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/scionproto/scion/go/proto");

struct DRKeyLvl1Req {
    isdas @0 :UInt64;     # Src ISD-AS of the requested DRKey
    valTime @1 :UInt32;   # Point in time where requested DRKey is valid. Used to identify the epoch
}

struct DRKeyLvl1Rep {
    isdas @0 :UInt64;      # Src ISD-AS of the DRKey
    epochBegin @1 :UInt32; # Begin of validity period of DRKey
    epochEnd @2 :UInt32;   # End of validity period of DRKey
    cipher @3 :Data;       # Encrypted DRKey
    certVerDst @4 :UInt64; # Version of cert of public key used to encrypt
}

struct DRKeyHost {
    type @0 :UInt8; # AddrType
    host @1 :Data;  # Host address
}

struct DRKeyLvl2Req {
    protocol @0 :Data;    # Protocol identifier
    reqType @1 :UInt8;    # Requested DRKeyProtoKeyType
    valTime @2 :UInt32;   # Point in time where requested DRKey is valid. Used to identify the epoch
    srcIA @3 :UInt64;     # Src ISD-AS of the requested DRKey
    dstIA @4 :UInt64;     # Dst ISD-AS of the requested DRKey
    srcHost :union {      # Src Host of the request DRKey (optional)
        unset @5 :Void;
        host @6 :DRKeyHost;
    }
    dstHost :union {      # Dst Host of the request DRKey (optional)
        unset @7 :Void;
        host @8 :DRKeyHost;
    }
    misc :union {         # Additional information for DRKey derivation (optional)
        unset @9 :Void;
        data @10 :Data;
    }
}

struct DRKeyLvl2Rep {
    timestamp @0 :UInt32;  # Timestamp
    drkey @1 :Data;        # Derived DRKey
    epochBegin @2 :UInt32; # Begin of validity period of DRKey
    epochEnd @3 :UInt32;   # End of validity period of DRKey
    misc :union {          # Additional information (optional)
        unset @4 :Void;
        data @5 :Data;
    }
}

struct DRKeyMgmt {
    union {
        unset @0 :Void;
        drkeyLvl1Req @1 :DRKeyLvl1Req;
        drkeyLvl1Rep @2 :DRKeyLvl1Rep;
        drkeyLvl2Req @3 :DRKeyLvl2Req;
        drkeyLvl2Rep @4 :DRKeyLvl2Rep;
    }
}
