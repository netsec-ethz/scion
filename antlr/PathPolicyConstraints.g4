
grammar PathPolicyConstraints;

fragment HEXA: [1-9a-fA-F][0-9a-fA-F]* | '0';

WHITESPACE: [ \t\r\n]+ -> skip;
ZERO: '0';
NUM: [1-9][0-9]*;
WILDCARDAS: '-' '0';
LEGACYAS: '-' NUM;
AS: '-' HEXA '_' HEXA '_' HEXA;
HASH: '#';

QUESTIONMARK: '?';
ELSE: ':';

PLUS: '+';
LPAR: '(';
RPAR: ')';
LBRACE: '{';
RBRACE: '}';

MONKEYTAIL: '@';
GLOBALPOLICY: 'G';
LOCALPOLICY: 'L';
REJECT: 'REJECT';

start
    : expression
    ;

query
    : LBRACE expression QUESTIONMARK expression ELSE expression RBRACE #IfElse
    | LBRACE expression QUESTIONMARK expression RBRACE #If
    ;

expression
    : LPAR expression RPAR # Parens
    | left=expression PLUS right=expression #ExpressionConcat
    | identifier # ExpressionIdentifier
    | query #ExpressionQuery
    ;

identifier: isd as HASH iface ',' iface MONKEYTAIL onepolicy;

isd
    : ZERO # WildcardISD
    | NUM  # ISD
    ;

as
    : WILDCARDAS # WildcardAS
    | LEGACYAS   # LegacyAS
    | AS         # AS
    ;

iface
    : ZERO # WildcardIFace
    | NUM  # IFace
    ;

onepolicy
    : GLOBALPOLICY policyindex # GlobalPolicy
    | LOCALPOLICY policyindex # LocalPolicy
    | ZERO # WildcardPolicy
    | REJECT # Reject
    ;

policyindex
    : NUM # PolicyIndex
    ;

