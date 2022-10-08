#shellcheck shell=sh
set -eu

CRED_FILE="${SHELLSPEC_TMPBASE}/credentials"
DUBP_FILE="${SHELLSPEC_TMPBASE}/mnemonic"
EWIF_FILE="${SHELLSPEC_TMPBASE}/username.ewif"
JWK_FILE="${SHELLSPEC_TMPBASE}/username.jwk"
NACL_FILE="${SHELLSPEC_TMPBASE}/username.nacl"
P2P_FILE="${SHELLSPEC_TMPBASE}/username.p2p"
PEM_FILE="${SHELLSPEC_TMPBASE}/username.pem"
PUBSEC_FILE="${SHELLSPEC_TMPBASE}/username.pubsec"
SEED_FILE="${SHELLSPEC_TMPBASE}/username.seed"
SSB_FILE="${SHELLSPEC_TMPBASE}/username.ssb"
WIF_FILE="${SHELLSPEC_TMPBASE}/username.wif"

gpg() {
  GNUPGHOME="${SHELLSPEC_TMPBASE}" command gpg "$@"
}

keygen() {
  if [ -x ./keygen ]; then
    GNUPGHOME="${SHELLSPEC_TMPBASE}" ./keygen "$@"
  elif [ -x ./bin/keygen ]; then
    GNUPGHOME="${SHELLSPEC_TMPBASE}" ./bin/keygen "$@"
  else
    GNUPGHOME="${SHELLSPEC_TMPBASE}" command keygen "$@"
  fi
}

Describe 'Dependency'
  Describe 'pinentry:'
    It 'is available'
      When run pinentry --help
      The output should include 'pinentry'
      The status should be success
      The stderr should be present
    End
  End
End

Describe 'keygen'
  Describe '--help:'
    It 'prints help'
      When run keygen --help
      The output should include 'usage:'
      The status should be success
      The stderr should equal ""
    End
  End
  Describe '--version:'
    It 'prints version'
      When run keygen --version
      The output should include 'v0.1.0'
      The status should be success
      The stderr should equal ""
    End
  End
  Describe '-p password username:'
    It 'prints base58 public key for user "username" and password "password"'
      When run keygen -p password username
      The output should include '4YLU1xQ9jzb7LzC6d91VZrYTEKS9N2j93Nnvcee6wxZG'
      The status should be success
      The stderr should equal ""
    End
  End
  Describe '-p password -s username:'
    It 'prints base58 secret key for user "username" and password "password"'
      When run keygen -p password -s username
      The output should include 'K5heSX4xGUPtRbxcZh6zbgaKbDv8FeVc9JuSNWtUs7C1oGNKqv7kQJ3DHdouTPzoW4duKKnuLQK8LbHKfN9fkjC'
      The status should be success
      The stderr should equal ""
    End
  End
  Describe '-k -p password username:'
    It 'prints base58 public and secret keys for user "username" and password "password"'
      When run keygen -k -p password username
      The output should include '4YLU1xQ9jzb7LzC6d91VZrYTEKS9N2j93Nnvcee6wxZG'
      The output should include 'K5heSX4xGUPtRbxcZh6zbgaKbDv8FeVc9JuSNWtUs7C1oGNKqv7kQJ3DHdouTPzoW4duKKnuLQK8LbHKfN9fkjC'
      The status should be success
      The stderr should equal ""
    End
  End
  Describe '-k -p password -t b36mf username:'
    It 'prints base36 multiformat public and secret keys for user "username" and password "password"'
      When run keygen -k -p password -t b36mf username
      The output should include 'k51qzi5uqu5dhhsbw068pust1xf763zdmyu2mb8rf6ewu2oz3in3a2g6pgtqy3'
      The output should include 'kmxn88f5mep5chc4tc002gyhtl9vgiluellgje285y2hn5a5kjdvqge7oeb0jryupt1q09w48h2nxg0ofcjco0wjwa824v3p9tvw6us9gdkb'
      The status should be success
      The stderr should equal ""
    End
  End
  Describe '-k -p password -t b58mf username:'
    It 'prints base58 multiformat public and secret keys for user "username" and password "password"'
      When run keygen -k -p password -t b58mf username
      The output should include 'z5AanNVJCxnJNiidpTZyuYzkQcrHRCyhxMV7Z4KYDV1MYy2ETMrEbUn'
      The output should include 'z4gg7xjCuszBpvNVcDAmNYVNrZxwXfDDQGoAShWmmQBkWRzZbR8A4ZBpkk4iTj3YSLBxvGZRf1AjCyGDdczhs7tshCsbFK4e'
      The status should be success
      The stderr should equal ""
    End
  End
  Describe '-k -p password -t b58mh username:'
    It 'prints base58 multihash public and secret keys for user "username" and password "password"'
      When run keygen -k -p password -t b58mh username
      The output should include '12D3KooWDMhdm5yrvtrbkshXFjkqLedHieUnPioczy9wzdnzquHC'
      The output should include '23jhTarm17VAHUwPkHD2Kv5sPfuQrsXSZUzKUrRkP2oP8bgnLjVExhG4AVoayCLxbXN4g2pjVG5qiJRucUtogbj7zGapz'
      The status should be success
      The stderr should equal ""
    End
  End
  Describe '-k -p password -t b64mh username:'
    It 'prints base64 multihash public and secret keys for user "username" and password "password"'
      When run keygen -k -p password -t b64mh username
      The output should include 'ACQIARIgNJoTbvcP+m51+XwxrmWqHaOpI1ZD0USwLjqAmV8Boas='
      The output should include 'CAESQA+XqCWjRqCjNe9oU3QA796bEH+T+rxgyPQ/EkXvE2MvNJoTbvcP+m51+XwxrmWqHaOpI1ZD0USwLjqAmV8Boas='
      The status should be success
      The stderr should equal ""
    End
  End
  Describe '-k -p password -t base58 username:'
    It 'prints base58 public and secret keys for user "username" and password "password"'
      When run keygen -k -p password -t base58 username
      The output should include '4YLU1xQ9jzb7LzC6d91VZrYTEKS9N2j93Nnvcee6wxZG'
      The output should include 'K5heSX4xGUPtRbxcZh6zbgaKbDv8FeVc9JuSNWtUs7C1oGNKqv7kQJ3DHdouTPzoW4duKKnuLQK8LbHKfN9fkjC'
      The status should be success
      The stderr should equal ""
    End
  End
  Describe '-k -p password -t base64 username:'
    It 'prints base64 public and secret keys for user "username" and password "password"'
      When run keygen -k -p password -t base64 username
      The output should include 'NJoTbvcP+m51+XwxrmWqHaOpI1ZD0USwLjqAmV8Boas='
      The output should include 'D5eoJaNGoKM172hTdADv3psQf5P6vGDI9D8SRe8TYy80mhNu9w/6bnX5fDGuZaodo6kjVkPRRLAuOoCZXwGhqw=='
      The status should be success
      The stderr should equal ""
    End
  End
  Describe '-k -p password -t duniter username:'
    It 'prints duniter public and secret keys for user "username" and password "password"'
      When run keygen -k -p password -t duniter username
      The output should include '4YLU1xQ9jzb7LzC6d91VZrYTEKS9N2j93Nnvcee6wxZG'
      The output should include 'K5heSX4xGUPtRbxcZh6zbgaKbDv8FeVc9JuSNWtUs7C1oGNKqv7kQJ3DHdouTPzoW4duKKnuLQK8LbHKfN9fkjC'
      The status should be success
      The stderr should equal ""
    End
  End
  Describe '-k -p password -t ipfs username:'
    It 'prints ipfs public and secret keys for user "username" and password "password"'
      When run keygen -k -p password -t ipfs username
      The output should include '12D3KooWDMhdm5yrvtrbkshXFjkqLedHieUnPioczy9wzdnzquHC'
      The output should include 'CAESQA+XqCWjRqCjNe9oU3QA796bEH+T+rxgyPQ/EkXvE2MvNJoTbvcP+m51+XwxrmWqHaOpI1ZD0USwLjqAmV8Boas='
      The status should be success
      The stderr should equal ""
    End
  End
  Describe '-k -p password -t jwk username:'
    It 'prints jwk public and secret keys for user "username" and password "password"'
      When run keygen -k -p password -t jwk username
      The output should include '{"crv":"Ed25519","kty":"OKP","x":"NJoTbvcP-m51-XwxrmWqHaOpI1ZD0USwLjqAmV8Boas"}'
      The output should include '{"crv":"Ed25519","d":"D5eoJaNGoKM172hTdADv3psQf5P6vGDI9D8SRe8TYy8","kty":"OKP","x":"NJoTbvcP-m51-XwxrmWqHaOpI1ZD0USwLjqAmV8Boas"}'
      The status should be success
      The stderr should equal ""
    End
  End
  Describe '-k -m "tongue cute mail ...":'
    It 'prints base58 public and secret keys for mnemonic "tongue cute mail ..."'
      When run keygen -k -m "tongue cute mail fossil great frozen same social weasel impact brush kind"
      The output should include '732SSfuwjB7jkt9th1zerGhphs6nknaCBCTozxUcPWPU'
      The output should include '4NHNg9KSp81nXAN4Gmwx4EZ9bCdahnJ9jozJa1cGj9oDvzx9kCtNSvasqTZVm6VJXBQxyakZ5uZnj8AS6g87kK3x'
      The status should be success
      The stderr should equal ""
    End
  End
  Describe "-i ${CRED_FILE} -k -v:"
    printf 'username\npassword\n' > "${CRED_FILE}"
    It 'prints base58 public and secret keys for username and password read from credentials file"'
      When run keygen -i "${CRED_FILE}" -k -v
      The output should include '4YLU1xQ9jzb7LzC6d91VZrYTEKS9N2j93Nnvcee6wxZG'
      The output should include 'K5heSX4xGUPtRbxcZh6zbgaKbDv8FeVc9JuSNWtUs7C1oGNKqv7kQJ3DHdouTPzoW4duKKnuLQK8LbHKfN9fkjC'
      The status should be success
      The stderr should include 'input file format detected: credentials'
    End
    rm -f "${CRED_FILE}"
  End
  Describe "-i ${DUBP_FILE} -k -v:"
    printf 'tongue cute mail fossil great frozen same social weasel impact brush kind\n' > "${DUBP_FILE}"
    It 'prints base58 public and secret keys for mnemonic read from dubp file"'
      When run keygen -i "${DUBP_FILE}" -k -v
      The output should include '732SSfuwjB7jkt9th1zerGhphs6nknaCBCTozxUcPWPU'
      The output should include '4NHNg9KSp81nXAN4Gmwx4EZ9bCdahnJ9jozJa1cGj9oDvzx9kCtNSvasqTZVm6VJXBQxyakZ5uZnj8AS6g87kK3x'
      The status should be success
      The stderr should include 'input file format detected: mnemonic'
    End
    rm -f "${DUBP_FILE}"
  End
  Describe "-f jwk -o ${JWK_FILE} -p password username:"
    rm -f "${JWK_FILE}"
    It 'writes secret key to a JWK file for user "username" and password "password"'
      When run keygen -f jwk -o "${JWK_FILE}" -p password username
      The path "${JWK_FILE}" should exist
      The contents of file "${JWK_FILE}" should include '{"crv":"Ed25519","d":"D5eoJaNGoKM172hTdADv3psQf5P6vGDI9D8SRe8TYy8","kty":"OKP","x":"NJoTbvcP-m51-XwxrmWqHaOpI1ZD0USwLjqAmV8Boas"}'
      The status should be success
      The stderr should equal ""
    End
  End
  Describe "-i ${JWK_FILE} -k -v:"
    It 'prints base58 public and secret keys for ed25519 key read from JWK file"'
      When run keygen -i "${JWK_FILE}" -k -v
      The output should include '4YLU1xQ9jzb7LzC6d91VZrYTEKS9N2j93Nnvcee6wxZG'
      The output should include 'K5heSX4xGUPtRbxcZh6zbgaKbDv8FeVc9JuSNWtUs7C1oGNKqv7kQJ3DHdouTPzoW4duKKnuLQK8LbHKfN9fkjC'
      The status should be success
      The stderr should include 'input file format detected: jwk'
    End
    rm -f "${JWK_FILE}"
  End
  Describe "-f nacl -o ${NACL_FILE} -p password username:"
    rm -f "${NACL_FILE}"
    It 'writes secret key to a libnacl file for user "username" and password "password"'
      When run keygen -f nacl -o "${NACL_FILE}" -p password username
      The path "${NACL_FILE}" should exist
      The contents of file "${NACL_FILE}" should include '{"priv": "0f97a825a346a0a335ef68537400efde9b107f93fabc60c8f43f1245ef13632f349a136ef70ffa6e75f97c31ae65aa1da3a9235643d144b02e3a80995f01a1ab", "verify": "349a136ef70ffa6e75f97c31ae65aa1da3a9235643d144b02e3a80995f01a1ab", "sign": "0f97a825a346a0a335ef68537400efde9b107f93fabc60c8f43f1245ef13632f"}'
      The status should be success
      The stderr should equal ""
    End
  End
  Describe "-i ${NACL_FILE} -k -v:"
    It 'prints base58 public and secret keys for ed25519 key read from libnacl file"'
      When run keygen -i "${NACL_FILE}" -k -v
      The output should include '4YLU1xQ9jzb7LzC6d91VZrYTEKS9N2j93Nnvcee6wxZG'
      The output should include 'K5heSX4xGUPtRbxcZh6zbgaKbDv8FeVc9JuSNWtUs7C1oGNKqv7kQJ3DHdouTPzoW4duKKnuLQK8LbHKfN9fkjC'
      The status should be success
      The stderr should include 'input file format detected: nacl'
    End
    rm -f "${NACL_FILE}"
  End
  Describe "-f ewif -o ${EWIF_FILE} -p password username:"
    rm -f "${EWIF_FILE}"
    It 'writes encrypted secret key to an EWIF file for user "username" and password "password"'
      When run keygen -f ewif -o "${EWIF_FILE}" -p password username
      The path "${EWIF_FILE}" should exist
      The contents of file "${EWIF_FILE}" should include 'Type: EWIF'
      The contents of file "${EWIF_FILE}" should include 'Version: 1'
      The contents of file "${EWIF_FILE}" should include 'Data: 2w6iPHHjrfGT3HWvNV1cw3ZpGXAAQtfYzRxDXUkyW2y5WBorLtDUY'
      The status should be success
      The stderr should equal ""
    End
  End
  Describe "-i ${EWIF_FILE} -k -p password -v:"
    It 'prints base58 public and secret keys for ed25519 key read from EWIF file encrypted with password "password"'
      When run keygen -i "${EWIF_FILE}" -k -p password -v username
      The output should include '4YLU1xQ9jzb7LzC6d91VZrYTEKS9N2j93Nnvcee6wxZG'
      The output should include 'K5heSX4xGUPtRbxcZh6zbgaKbDv8FeVc9JuSNWtUs7C1oGNKqv7kQJ3DHdouTPzoW4duKKnuLQK8LbHKfN9fkjC'
      The status should be success
      The stderr should include 'input file format detected: ewif'
    End
    rm -f "${EWIF_FILE}"
  End
  Describe "-o ${PEM_FILE} -p password username:"
    rm -f "${PEM_FILE}"
    It 'writes pkcs8 secret key to a pem file for user "username" and password "password"'
      When run keygen -o "${PEM_FILE}" -p password username
      The path "${PEM_FILE}" should exist
      The contents of file "${PEM_FILE}" should include '-----BEGIN PRIVATE KEY-----'
      The contents of file "${PEM_FILE}" should include 'MC4CAQAwBQYDK2VwBCIEIA+XqCWjRqCjNe9oU3QA796bEH+T+rxgyPQ/EkXvE2Mv'
      The contents of file "${PEM_FILE}" should include '-----END PRIVATE KEY-----'
      The status should be success
      The stderr should equal ""
    End
  End
  Describe "-f pem -o ${PEM_FILE} -p password username:"
    rm -f "${PEM_FILE}"
    It 'writes pkcs8 secret key to a pem file for user "username" and password "password"'
      When run keygen -f pem -o "${PEM_FILE}" -p password username
      The path "${PEM_FILE}" should exist
      The contents of file "${PEM_FILE}" should include '-----BEGIN PRIVATE KEY-----'
      The contents of file "${PEM_FILE}" should include 'MC4CAQAwBQYDK2VwBCIEIA+XqCWjRqCjNe9oU3QA796bEH+T+rxgyPQ/EkXvE2Mv'
      The contents of file "${PEM_FILE}" should include '-----END PRIVATE KEY-----'
      The status should be success
      The stderr should equal ""
    End
  End
  Describe "-i ${PEM_FILE} -k -v:"
    It 'prints base58 public and secret keys for ed25519 key read from pkcs8 pem file"'
      When run keygen -i "${PEM_FILE}" -k -v
      The output should include '4YLU1xQ9jzb7LzC6d91VZrYTEKS9N2j93Nnvcee6wxZG'
      The output should include 'K5heSX4xGUPtRbxcZh6zbgaKbDv8FeVc9JuSNWtUs7C1oGNKqv7kQJ3DHdouTPzoW4duKKnuLQK8LbHKfN9fkjC'
      The status should be success
      The stderr should include 'input file format detected: pem'
    End
    rm -f "${PEM_FILE}"
  End
  Describe "-f p2p -o ${P2P_FILE} -p password username:"
    rm -f "${P2P_FILE}"
    It 'writes libp2p secret key to a p2p file for user "username" and password "password"'
      decode_p2p() {
        xxd -p "${P2P_FILE}"
      }
      not_xxd() {
        ! which xxd >/dev/null 2>&1
      }
      Skip if 'You should install xxd' not_xxd
      When run keygen -f p2p -o "${P2P_FILE}" -p password username
      The path "${P2P_FILE}" should exist
      The result of function decode_p2p should include '080112400f97a825a346a0a335ef68537400efde9b107f93fabc60c8f43f'
      The result of function decode_p2p should include '1245ef13632f349a136ef70ffa6e75f97c31ae65aa1da3a9235643d144b0'
      The result of function decode_p2p should include '2e3a80995f01a1ab'
      The status should be success
      The stderr should equal ""
    End
  End
  Describe "-i ${P2P_FILE} -k -v:"
    It 'prints base58 public and secret keys for ed25519 key read from p2p file"'
      When run keygen -i "${P2P_FILE}" -k -v
      The output should include '4YLU1xQ9jzb7LzC6d91VZrYTEKS9N2j93Nnvcee6wxZG'
      The output should include 'K5heSX4xGUPtRbxcZh6zbgaKbDv8FeVc9JuSNWtUs7C1oGNKqv7kQJ3DHdouTPzoW4duKKnuLQK8LbHKfN9fkjC'
      The status should be success
      The stderr should include 'input file format detected: p2p'
    End
    rm -f "${P2P_FILE}"
  End
  Describe "-f pubsec -o ${PUBSEC_FILE} -p password username:"
    rm -f "${PUBSEC_FILE}"
    It 'writes base58 public and secret keys to a pubsec file for user "username" and password "password"'
      When run keygen -f pubsec -o "${PUBSEC_FILE}" -p password username
      The path "${PUBSEC_FILE}" should exist
      The contents of file "${PUBSEC_FILE}" should include 'Type: PubSec'
      The contents of file "${PUBSEC_FILE}" should include 'Version: 1'
      The contents of file "${PUBSEC_FILE}" should include 'pub: 4YLU1xQ9jzb7LzC6d91VZrYTEKS9N2j93Nnvcee6wxZG'
      The contents of file "${PUBSEC_FILE}" should include 'sec: K5heSX4xGUPtRbxcZh6zbgaKbDv8FeVc9JuSNWtUs7C1oGNKqv7kQJ3DHdouTPzoW4duKKnuLQK8LbHKfN9fkjC'
      The status should be success
      The stderr should equal ""
    End
  End
  Describe "-o ${PUBSEC_FILE} -p password -t duniter username:"
    rm -f "${PUBSEC_FILE}"
    It 'writes duniter public and secret keys to a pubsec file for user "username" and password "password"'
      When run keygen -o "${PUBSEC_FILE}" -p password -t duniter username
      The path "${PUBSEC_FILE}" should exist
      The contents of file "${PUBSEC_FILE}" should include 'Type: PubSec'
      The contents of file "${PUBSEC_FILE}" should include 'Version: 1'
      The contents of file "${PUBSEC_FILE}" should include 'pub: 4YLU1xQ9jzb7LzC6d91VZrYTEKS9N2j93Nnvcee6wxZG'
      The contents of file "${PUBSEC_FILE}" should include 'sec: K5heSX4xGUPtRbxcZh6zbgaKbDv8FeVc9JuSNWtUs7C1oGNKqv7kQJ3DHdouTPzoW4duKKnuLQK8LbHKfN9fkjC'
      The status should be success
      The stderr should equal ""
    End
  End
  Describe "-i ${PUBSEC_FILE} -k -t ipfs -v:"
    It 'prints ipfs public and secret keys for base58 keys read in a pubsec file'
      When run keygen -i "${PUBSEC_FILE}" -k -t ipfs -v
      The output should include '12D3KooWDMhdm5yrvtrbkshXFjkqLedHieUnPioczy9wzdnzquHC'
      The output should include 'CAESQA+XqCWjRqCjNe9oU3QA796bEH+T+rxgyPQ/EkXvE2MvNJoTbvcP+m51+XwxrmWqHaOpI1ZD0USwLjqAmV8Boas='
      The status should be success
      The stderr should include 'input file format detected: pubsec'
    End
    rm -f "${PUBSEC_FILE}"
  End
  Describe "-i ${SSB_FILE} -k -v:"
    printf '{ "curve": "ed25519", "public": "cFVodZoKwLcmXbM6UeASdl8+7+Uo8PNOuFnlcqk7qUc=.ed25519", "private": "lUqlXYxjkM0/ljtGnwoM0CfP6ORA2DKZnzsQ4dJ1tKJwVWh1mgrAtyZdszpR4BJ2Xz7v5Sjw8064WeVyqTupRw==.ed25519", "id": "@cFVodZoKwLcmXbM6UeASdl8+7+Uo8PNOuFnlcqk7qUc=.ed25519" }\n' > "${SSB_FILE}"
    It 'prints prefixed base58 public and secret keys for ed25519 key read from ssb file"'
      When run keygen -i "${SSB_FILE}" -k -v
      The output should include '8ZWCTFBUczYRucyvTgJL6oefj28u243LYU4ZjYKn4XDG'
      The output should include '3z7vcMHQhnVPTEEaFQ5gxn2NHkmJsFHkZ4W2aoAvt3Jt5ZYhFV1M6NEkm7Lr75pEF61oSkQVsaih9cQWBP2JmbVQ'
      The status should be success
      The stderr should include 'input file format detected: ssb'
    End
    rm -f "${SSB_FILE}"
  End
  Describe "-f seed -o ${SEED_FILE} -p password username:"
    rm -f "${SEED_FILE}"
    It 'writes encoded secret key to a wif file for user "username" and password "password"'
      When run keygen -f seed -o "${SEED_FILE}" -p password username
      The path "${SEED_FILE}" should exist
      The contents of file "${SEED_FILE}" should include '0f97a825a346a0a335ef68537400efde9b107f93fabc60c8f43f1245ef13632f'
      The status should be success
      The stderr should equal ""
    End
  End
  Describe "-i ${SEED_FILE} -k -v:"
    It 'prints base58 public and secret keys for ed25519 key read from seed file"'
      When run keygen -i "${SEED_FILE}" -k -v
      The output should include '4YLU1xQ9jzb7LzC6d91VZrYTEKS9N2j93Nnvcee6wxZG'
      The output should include 'K5heSX4xGUPtRbxcZh6zbgaKbDv8FeVc9JuSNWtUs7C1oGNKqv7kQJ3DHdouTPzoW4duKKnuLQK8LbHKfN9fkjC'
      The status should be success
      The stderr should include 'input file format detected: seed'
    End
    rm -f "${SEED_FILE}"
  End
  Describe "-f wif -o ${WIF_FILE} -p password username:"
    rm -f "${WIF_FILE}"
    It 'writes encoded secret key to a wif file for user "username" and password "password"'
      When run keygen -f wif -o "${WIF_FILE}" -p password username
      The path "${WIF_FILE}" should exist
      The contents of file "${WIF_FILE}" should include 'Type: WIF'
      The contents of file "${WIF_FILE}" should include 'Version: 1'
      The contents of file "${WIF_FILE}" should include 'Data: 7972e1McMMURp9R1MDCH1UMEEnF2bKAjc2WtEW3JyAVwMVT'
      The status should be success
      The stderr should equal ""
    End
  End
  Describe "-i ${WIF_FILE} -k -v:"
    It 'prints base58 public and secret keys for ed25519 key read from WIF file"'
      When run keygen -i "${WIF_FILE}" -k -v
      The output should include '4YLU1xQ9jzb7LzC6d91VZrYTEKS9N2j93Nnvcee6wxZG'
      The output should include 'K5heSX4xGUPtRbxcZh6zbgaKbDv8FeVc9JuSNWtUs7C1oGNKqv7kQJ3DHdouTPzoW4duKKnuLQK8LbHKfN9fkjC'
      The status should be success
      The stderr should include 'input file format detected: wif'
    End
    rm -f "${WIF_FILE}"
  End
  Describe '-b 0 -p password -t gpg username:'
    It 'creates a password protected gpg key for user "username"'
      Skip "You should implement it !"
      When run keygen -b 0 -p password -t pgp username
      The status should be success
    End
  End
  Describe '-g -k username:'
    gpg --batch --import --quiet specs/username.asc
    It 'prints base58 public and secret keys for ed25519 gpg key matching uid "username"'
      When run keygen -g -k username
      The output should include '2g5UL2zhkn5i7oNYDpWo3fBuWvRYVU1AbMtdVmnGzPNv'
      The output should include '5WtYFfA26nTfG496gAKhkrLYUMMnwXexmE1E8Q7PvtQEyscHfirsdMzW34zDp7WEkt3exNEVwoG4ajZYrm62wpi2'
      The status should be success
      The stderr should equal ""
    End
    gpg --batch --delete-secret-and-public-key --yes 4D1CDB77E91FFCD81B10F9A7079E5BF4721944FB
  End
  Describe '-g -k -p password username@protected:'
    gpg --batch --import --quiet specs/username_protected.asc
    It 'prints public and secret keys for ed25519 gpg key matching uid "username@protected" and locked with password "password"'
      When run keygen -g -k -p password username@protected
      The output should include 'C1cRu7yb5rZhsmRHQkeZxusAhtYYJypcnXpY3HycEKsU'
      The output should include 'VWaEdDroSCoagJDsBnDNUtXJtKAJYdqL6XKNiomz8DtiyF44FvpiMmhidXt2j8HhDBKPZ67xBGcZPnj4Myk6cB8'
      The status should be success
      The stderr should equal ""
    End
    gpg --batch --delete-secret-and-public-key --yes 6AF574897D4979B7956AC31B6222A29CBC31A087
  End
  Describe '-g -k usersame:'
    gpg --batch --import --quiet specs/usersame.asc
    It 'prints base58 public and secret keys for rsa gpg key matching uid "usersame"'
      When run keygen -g -k usersame
      The output should include 'EGdSY9fKom7MnvHALNQU7LUoEEE2sju5ntL9eRXJ5tTM'
      The output should include '4jPG9MH9LVA7HhcfFs41pXVjxDQLdgu3Mtc64Ph6U3vUMNWfJqTBdFFaviq5r6zJC8PpWUiaUhjVnYAa2E9UrFTZ'
      The status should be success
      The stderr should equal ""
    End
    gpg --batch --delete-secret-and-public-key --yes 845E099CFD17FD07346F9D26CAB2E65557C656DF
  End
  Describe '-g -k -p password usersame@protected:'
    gpg --batch --import --quiet specs/usersame_protected.asc
    It 'prints public and secret keys for rsa gpg key matching uid "usersame@protected" and locked with password "password"'
      When run keygen -g -k -p password usersame@protected
      The output should include '6KNNPBxkMYnccYvpePBKDewZ3JiQnmWA4e7QSsvZUzLM'
      The output should include '4q4SM9qoWc2eLtfYWs7K9hb7oSCNjCLc8U6ELNrScteVGVnSBP4YMDM5V8RPsHURqCqP5ndPkqGoB74cmRxfJro7'
      The status should be success
      The stderr should equal ""
    End
    gpg --batch --delete-secret-and-public-key --yes 78BC5CD37664E5C1AA85AC97ABC22BF0C070C9AD
  End
  Describe "-g -o ${PUBSEC_FILE} -t duniter username:"
    rm -f "${PUBSEC_FILE}"
    gpg --batch --import --quiet specs/username.asc
    It 'writes duniter public and secret keys to a pubsec file for gpg key matching uid "username"'
      When run keygen -g -o "${PUBSEC_FILE}" -t duniter username
      The path "${PUBSEC_FILE}" should exist
      The contents of file "${PUBSEC_FILE}" should include 'Type: PubSec'
      The contents of file "${PUBSEC_FILE}" should include 'Version: 1'
      The contents of file "${PUBSEC_FILE}" should include 'pub: 2g5UL2zhkn5i7oNYDpWo3fBuWvRYVU1AbMtdVmnGzPNv'
      The contents of file "${PUBSEC_FILE}" should include 'sec: 5WtYFfA26nTfG496gAKhkrLYUMMnwXexmE1E8Q7PvtQEyscHfirsdMzW34zDp7WEkt3exNEVwoG4ajZYrm62wpi2'
      The status should be success
      The stderr should equal ""
    End
    gpg --batch --delete-secret-and-public-key --yes 4D1CDB77E91FFCD81B10F9A7079E5BF4721944FB
  End
End
