@0xf85d2602085656c1;

using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/scionproto/scion/go/proto");


struct DRKeyLvl1Req {
    dstIA @0 :UInt64;     # Dst ISD-AS of the requested DRKey
    valTime @1 :UInt32;   # Point in time where requested DRKey is valid. Used to identify the epoch
    timestamp @2 :UInt32; # Point in time when the request was created
}

struct DRKeyLvl1Rep {
    dstIA @0 :UInt64;      # Dst ISD-AS of the DRKey
    epochBegin @1 :UInt32; # Begin of validity period of DRKey
    epochEnd @2 :UInt32;   # End of validity period of DRKey
    cipher @3 :Data;       # Encrypted DRKey
    nonce @4 :Data;        # Nonce used for encryption
    certVerDst @5 :UInt64; # Version of cert of public key used to encrypt
    timestamp @6 :UInt32;  # Creation time of this reply
}

struct DRKeyHost {
    type @0 :UInt8; # AddrType
    host @1 :Data;  # Host address
}

struct DRKeyLvl2Req {
    protocol @0 :Text;      # Protocol identifier
    reqType @1 :UInt8;      # Requested DRKeyProtoKeyType
    valTime @2 :UInt32;     # Point in time where requested DRKey is valid. Used to identify the epoch
    srcIA @3 :UInt64;       # Src ISD-AS of the requested DRKey
    dstIA @4 :UInt64;       # Dst ISD-AS of the requested DRKey
    srcHost @5 :DRKeyHost;  # Src Host of the request DRKey (optional)
    dstHost @6 :DRKeyHost;  # Dst Host of the request DRKey (optional)
    misc @7 :Data;          # Additional information (optional)
}

struct DRKeyLvl2Rep {
    timestamp @0 :UInt32;  # Timestamp
    drkey @1 :Data;        # Derived DRKey
    epochBegin @2 :UInt32; # Begin of validity period of DRKey
    epochEnd @3 :UInt32;   # End of validity period of DRKey
    misc @4 :Data;         # Additional information (optional)
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

