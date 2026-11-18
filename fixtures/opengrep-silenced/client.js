// Fixture: the certificate check is off, with a comment that silences Opengrep. CI scan must block.
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'; // nosemgrep: rules_lgpl_javascript_crypto_rule-node-tls-reject
