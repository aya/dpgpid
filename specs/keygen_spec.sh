#shellcheck shell=sh
set -eu

PB2_FILE="${SHELLSPEC_TMPBASE}/key.pb2"
PEM_FILE="${SHELLSPEC_TMPBASE}/key.pem"
PUBSEC_FILE="${SHELLSPEC_TMPBASE}/key.pubsec"

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
  Describe 'python3:'
    It 'is available'
      When run python3 --help
      The output should include 'python3'
      The status should be success
      The stderr should equal ""
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
      The output should include 'v0.0.3'
      The status should be success
      The stderr should equal ""
    End
  End
  Describe 'username password:'
    It 'prints base58 public key for user "username" with password "password"'
      When run keygen username password
      The output should include '4YLU1xQ9jzb7LzC6d91VZrYTEKS9N2j93Nnvcee6wxZG'
      The status should be success
      The stderr should equal ""
    End
  End
  Describe '-p username password:'
    It 'prints prefixed base58 public key for user "username" with password "password"'
      When run keygen -p username password
      The output should include 'pub: 4YLU1xQ9jzb7LzC6d91VZrYTEKS9N2j93Nnvcee6wxZG'
      The status should be success
      The stderr should equal ""
    End
  End
  Describe '-s username password:'
    It 'prints base58 secret key for user "username" with password "password"'
      When run keygen -s username password
      The output should include 'K5heSX4xGUPtRbxcZh6zbgaKbDv8FeVc9JuSNWtUs7C1oGNKqv7kQJ3DHdouTPzoW4duKKnuLQK8LbHKfN9fkjC'
      The status should be success
      The stderr should equal ""
    End
  End
  Describe '-ps username password:'
    It 'prints prefixed base58 secret key for user "username" with password "password"'
      When run keygen -ps username password
      The output should include 'sec: K5heSX4xGUPtRbxcZh6zbgaKbDv8FeVc9JuSNWtUs7C1oGNKqv7kQJ3DHdouTPzoW4duKKnuLQK8LbHKfN9fkjC'
      The status should be success
      The stderr should equal ""
    End
  End
  Describe '-k username password:'
    It 'prints base58 public and secret keys for user "username" with password "password"'
      When run keygen -k username password
      The output should include '4YLU1xQ9jzb7LzC6d91VZrYTEKS9N2j93Nnvcee6wxZG'
      The output should include 'K5heSX4xGUPtRbxcZh6zbgaKbDv8FeVc9JuSNWtUs7C1oGNKqv7kQJ3DHdouTPzoW4duKKnuLQK8LbHKfN9fkjC'
      The status should be success
      The stderr should equal ""
    End
  End
  Describe '-pk username password:'
    It 'prints prefixed base58 public and secret keys for user "username" with password "password"'
      When run keygen -pk username password
      The output should include 'pub: 4YLU1xQ9jzb7LzC6d91VZrYTEKS9N2j93Nnvcee6wxZG'
      The output should include 'sec: K5heSX4xGUPtRbxcZh6zbgaKbDv8FeVc9JuSNWtUs7C1oGNKqv7kQJ3DHdouTPzoW4duKKnuLQK8LbHKfN9fkjC'
      The status should be success
      The stderr should equal ""
    End
  End
  Describe '-t base58 -pk username password:'
    It 'prints prefixed base58 public and secret keys for user "username" with password "password"'
      When run keygen -t base58 -pk username password
      The output should include 'pub: 4YLU1xQ9jzb7LzC6d91VZrYTEKS9N2j93Nnvcee6wxZG'
      The output should include 'sec: K5heSX4xGUPtRbxcZh6zbgaKbDv8FeVc9JuSNWtUs7C1oGNKqv7kQJ3DHdouTPzoW4duKKnuLQK8LbHKfN9fkjC'
      The status should be success
      The stderr should equal ""
    End
  End
  Describe '-t base64 -pk username password:'
    It 'prints prefixed base64 public and secret keys for user "username" with password "password"'
      When run keygen -t base64 -pk username password
      The output should include 'pub: NJoTbvcP+m51+XwxrmWqHaOpI1ZD0USwLjqAmV8Boas='
      The output should include 'sec: D5eoJaNGoKM172hTdADv3psQf5P6vGDI9D8SRe8TYy80mhNu9w/6bnX5fDGuZaodo6kjVkPRRLAuOoCZXwGhqw=='
      The status should be success
      The stderr should equal ""
    End
  End
  Describe '-t duniter -pk username password:'
    It 'prints prefixed duniter public and secret keys for user "username" with password "password"'
      When run keygen -t duniter -pk username password
      The output should include 'pub: 4YLU1xQ9jzb7LzC6d91VZrYTEKS9N2j93Nnvcee6wxZG'
      The output should include 'sec: K5heSX4xGUPtRbxcZh6zbgaKbDv8FeVc9JuSNWtUs7C1oGNKqv7kQJ3DHdouTPzoW4duKKnuLQK8LbHKfN9fkjC'
      The status should be success
      The stderr should equal ""
    End
  End
  Describe '-t ipfs -pk username password:'
    It 'prints prefixed ipfs public and secret keys for user "username" with password "password"'
      When run keygen -t ipfs -pk username password
      The output should include 'PeerID: 12D3KooWDMhdm5yrvtrbkshXFjkqLedHieUnPioczy9wzdnzquHC'
      The output should include 'PrivKEY: CAESQA+XqCWjRqCjNe9oU3QA796bEH+T+rxgyPQ/EkXvE2MvNJoTbvcP+m51+XwxrmWqHaOpI1ZD0USwLjqAmV8Boas='
      The status should be success
      The stderr should equal ""
    End
  End
  Describe "-o ${PEM_FILE} username password:"
    rm -f "${PEM_FILE}"
    It 'writes pkcs8 secret key to a pem file for user "username" with password "password"'
      When run keygen -o "${PEM_FILE}" -t ipfs username password
      The path "${PEM_FILE}" should exist
      The contents of file "${PEM_FILE}" should include '-----BEGIN PRIVATE KEY-----'
      The contents of file "${PEM_FILE}" should include 'MC4CAQAwBQYDK2VwBCIEIA+XqCWjRqCjNe9oU3QA796bEH+T+rxgyPQ/EkXvE2Mv'
      The contents of file "${PEM_FILE}" should include '-----END PRIVATE KEY-----'
      The status should be success
      The stderr should equal ""
    End
  End
  Describe "-f pem -o ${PEM_FILE} username password:"
    rm -f "${PEM_FILE}"
    It 'writes pkcs8 secret key to a pem file for user "username" with password "password"'
      When run keygen -f pem -o "${PEM_FILE}" -t ipfs username password
      The path "${PEM_FILE}" should exist
      The contents of file "${PEM_FILE}" should include '-----BEGIN PRIVATE KEY-----'
      The contents of file "${PEM_FILE}" should include 'MC4CAQAwBQYDK2VwBCIEIA+XqCWjRqCjNe9oU3QA796bEH+T+rxgyPQ/EkXvE2Mv'
      The contents of file "${PEM_FILE}" should include '-----END PRIVATE KEY-----'
      The status should be success
      The stderr should equal ""
    End
  End
  Describe "-f pb2 -o ${PB2_FILE} username password:"
    rm -f "${PB2_FILE}"
    It 'writes protobuf2 secret key to a pb2 file for user "username" with password "password"'
      decode_pb2() {
        xxd -ps "${PB2_FILE}"
      }
      not_xxd() {
        ! which xxd >/dev/null 2>&1
      }
      Skip if 'You should install xxd' not_xxd
      When run keygen -f pb2 -o "${PB2_FILE}" username password
      The path "${PB2_FILE}" should exist
      The result of function decode_pb2 should include '080112400f97a825a346a0a335ef68537400efde9b107f93fabc60c8f43f'
      The result of function decode_pb2 should include '1245ef13632f349a136ef70ffa6e75f97c31ae65aa1da3a9235643d144b0'
      The result of function decode_pb2 should include '2e3a80995f01a1ab'
      The status should be success
      The stderr should equal ""
    End
  End
  Describe "-f pubsec -o ${PUBSEC_FILE} username password:"
    rm -f "${PUBSEC_FILE}"
    It 'writes base58 public and secret keys to a pubsec file for user "username" with password "password"'
      When run keygen -f pubsec -o "${PUBSEC_FILE}" username password
      The path "${PUBSEC_FILE}" should exist
      The contents of file "${PUBSEC_FILE}" should include 'Type: PubSec'
      The contents of file "${PUBSEC_FILE}" should include 'Version: 1'
      The contents of file "${PUBSEC_FILE}" should include 'pub: 4YLU1xQ9jzb7LzC6d91VZrYTEKS9N2j93Nnvcee6wxZG'
      The contents of file "${PUBSEC_FILE}" should include 'sec: K5heSX4xGUPtRbxcZh6zbgaKbDv8FeVc9JuSNWtUs7C1oGNKqv7kQJ3DHdouTPzoW4duKKnuLQK8LbHKfN9fkjC'
      The status should be success
      The stderr should equal ""
    End
  End
  Describe "-o ${PUBSEC_FILE} -t duniter username password:"
    rm -f "${PUBSEC_FILE}"
    It 'writes duniter public and secret keys to a pubsec file for user "username" with password "password"'
      When run keygen -o "${PUBSEC_FILE}" -t duniter username password
      The path "${PUBSEC_FILE}" should exist
      The contents of file "${PUBSEC_FILE}" should include 'Type: PubSec'
      The contents of file "${PUBSEC_FILE}" should include 'Version: 1'
      The contents of file "${PUBSEC_FILE}" should include 'pub: 4YLU1xQ9jzb7LzC6d91VZrYTEKS9N2j93Nnvcee6wxZG'
      The contents of file "${PUBSEC_FILE}" should include 'sec: K5heSX4xGUPtRbxcZh6zbgaKbDv8FeVc9JuSNWtUs7C1oGNKqv7kQJ3DHdouTPzoW4duKKnuLQK8LbHKfN9fkjC'
      The status should be success
      The stderr should equal ""
    End
  End
  Describe "-i ${PUBSEC_FILE} -t ipfs -pk:"
    It 'prints prefixed ipfs public and secret keys for base58 keys read in a pubsec file'
      When run keygen -i "${PUBSEC_FILE}" -t ipfs -pk
      The output should include 'PeerID: 12D3KooWDMhdm5yrvtrbkshXFjkqLedHieUnPioczy9wzdnzquHC'
      The output should include 'PrivKEY: CAESQA+XqCWjRqCjNe9oU3QA796bEH+T+rxgyPQ/EkXvE2MvNJoTbvcP+m51+XwxrmWqHaOpI1ZD0USwLjqAmV8Boas='
      The status should be success
      The stderr should equal ""
    End
  End
  Describe '-t gpg username password birthday:'
    It 'creates a password protected gpg key for user username'
      Skip "You should implement it !"
      When run keygen -t pgp username password birthday
      The status should be success
    End
  End
  Describe '-pkg username:'
    gpg --batch --import --quiet specs/username.asc
    It 'prints prefixed base58 public and secret keys for ed25519 gpg key matching "username"'
      When run keygen -pkg username
      The output should include 'pub: 2g5UL2zhkn5i7oNYDpWo3fBuWvRYVU1AbMtdVmnGzPNv'
      The output should include 'sec: 5WtYFfA26nTfG496gAKhkrLYUMMnwXexmE1E8Q7PvtQEyscHfirsdMzW34zDp7WEkt3exNEVwoG4ajZYrm62wpi2'
      The status should be success
      The stderr should equal ""
    End
    gpg --batch --delete-secret-and-public-key --yes 4D1CDB77E91FFCD81B10F9A7079E5BF4721944FB
  End
  Describe '-pkg username@protected password:'
    gpg --batch --import --quiet specs/username_protected.asc
    It 'prints prefixed public and secret keys for ed25519 gpg key matching "username@protected" locked with "password"'
      When run keygen -pkg username@protected password
      The output should include 'pub: C1cRu7yb5rZhsmRHQkeZxusAhtYYJypcnXpY3HycEKsU'
      The output should include 'sec: VWaEdDroSCoagJDsBnDNUtXJtKAJYdqL6XKNiomz8DtiyF44FvpiMmhidXt2j8HhDBKPZ67xBGcZPnj4Myk6cB8'
      The status should be success
      The stderr should equal ""
    End
    gpg --batch --delete-secret-and-public-key --yes 6AF574897D4979B7956AC31B6222A29CBC31A087
  End
  Describe '-pkg usersame:'
    gpg --batch --import --quiet specs/usersame.asc
    It 'prints prefixed base58 public and secret keys for rsa gpg key matching "usersame"'
      When run keygen -pkg usersame
      The output should include 'pub: 4NxSjjys6bo8mhM919MkvNkNPFu4zpFyxu1r7yJ39K87'
      The output should include 'sec: 2cLFNeXiqcKKv5BF9JVTwtWmFHLvjDkJkrCyQbST9oYbsQLHsVaUAzbwrv5YfzQcPHu6e6XUzdstKy4kLhgDSGiw'
      The status should be success
      The stderr should equal ""
    End
    gpg --batch --delete-secret-and-public-key --yes 845E099CFD17FD07346F9D26CAB2E65557C656DF
  End
  Describe '-pkg usersame@protected password:'
    gpg --batch --import --quiet specs/usersame_protected.asc
    It 'prints prefixed public and secret keys for rsa gpg key matching "usersame@protected" locked with "password"'
      When run keygen -pkg usersame@protected password
      The output should include 'pub: 5kh2uqNTuYsLN7fwSRP3JWM4Hotcpdkb7frRNZwo9BPp'
      The output should include 'sec: LdWjjkP7gRzH4k4gNkQs2er26bE2Dhz7cGPE8fMNixe1Uv2ZHbo1QtyZxmDeTP77y6HVLbHNoXdMTHdo6ip9PHk'
      The status should be success
      The stderr should equal ""
    End
    gpg --batch --delete-secret-and-public-key --yes 78BC5CD37664E5C1AA85AC97ABC22BF0C070C9AD
  End
End
