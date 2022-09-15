#shellcheck shell=sh
set -eu

TEST_DIR="$(mktemp -d)"
DUNITER_PUBSEC_FILE="${TEST_DIR}/duniter.pubsec"
IPFS_PEM_FILE="${TEST_DIR}/ipfs.pem"

gpg() {
  GNUPGHOME="${TEST_DIR}" command gpg "$@"
}

keygen() {
  if [ -x ./keygen ]; then
    GNUPGHOME="${TEST_DIR}" ./keygen "$@"
  elif [ -x ./bin/keygen ]; then
    GNUPGHOME="${TEST_DIR}" ./bin/keygen "$@"
  else
    GNUPGHOME="${TEST_DIR}" command keygen "$@"
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
  Describe '-t duniter -pk username password:'
    It 'prints prefixed duniter public key for user "username" with password "password"'
      When run keygen -t duniter -pk username password
      The output should include 'pub: 4YLU1xQ9jzb7LzC6d91VZrYTEKS9N2j93Nnvcee6wxZG'
      The output should include 'sec: K5heSX4xGUPtRbxcZh6zbgaKbDv8FeVc9JuSNWtUs7C1oGNKqv7kQJ3DHdouTPzoW4duKKnuLQK8LbHKfN9fkjC'
      The status should be success
      The stderr should equal ""
    End
  End
  Describe "-o ${DUNITER_PUBSEC_FILE} -t duniter username password:"
    rm -f "${DUNITER_PUBSEC_FILE}"
    It 'writes duniter keys to file for user "username" with password "password"'
      When run keygen -o "${DUNITER_PUBSEC_FILE}" -t duniter username password
      The path "${DUNITER_PUBSEC_FILE}" should exist
      The contents of file "${DUNITER_PUBSEC_FILE}" should include 'pub: 4YLU1xQ9jzb7LzC6d91VZrYTEKS9N2j93Nnvcee6wxZG'
      The contents of file "${DUNITER_PUBSEC_FILE}" should include 'sec: K5heSX4xGUPtRbxcZh6zbgaKbDv8FeVc9JuSNWtUs7C1oGNKqv7kQJ3DHdouTPzoW4duKKnuLQK8LbHKfN9fkjC'
      The status should be success
      The stderr should equal ""
    End
  End
  Describe "-i ${DUNITER_PUBSEC_FILE} -t ipfs -pk:"
    It 'prints prefixed ipfs keys for duniter keys read in pubsec file'
      When run keygen -i "${DUNITER_PUBSEC_FILE}" -t ipfs -pk
      The output should include 'PeerID: 12D3KooWDMhdm5yrvtrbkshXFjkqLedHieUnPioczy9wzdnzquHC'
      The output should include 'PrivKEY: CAESQA+XqCWjRqCjNe9oU3QA796bEH+T+rxgyPQ/EkXvE2MvNJoTbvcP+m51+XwxrmWqHaOpI1ZD0USwLjqAmV8Boas='
      The status should be success
      The stderr should equal ""
    End
  End
  Describe "-i ${DUNITER_PUBSEC_FILE} -o ${IPFS_PEM_FILE} -t ipfs:"
    It 'writes ipfs keys to file for duniter keys read in pubsec file'
      When run keygen -i "${DUNITER_PUBSEC_FILE}" -o "${IPFS_PEM_FILE}" -t ipfs
      The path "${IPFS_PEM_FILE}" should exist
      The contents of file "${IPFS_PEM_FILE}" should include '-----BEGIN PRIVATE KEY-----'
      The contents of file "${IPFS_PEM_FILE}" should include 'MC4CAQAwBQYDK2VwBCIEIA+XqCWjRqCjNe9oU3QA796bEH+T+rxgyPQ/EkXvE2Mv'
      The contents of file "${IPFS_PEM_FILE}" should include '-----END PRIVATE KEY-----'
      The status should be success
      The stderr should equal ""
    End
    rm -f "${DUNITER_PUBSEC_FILE}" "${IPFS_PEM_FILE}"
  End
  Describe '-t ipfs username password:'
    It 'prints ipfs public key for user "username" with password "password"'
      When run keygen -t ipfs username password
      The output should include '12D3KooWDMhdm5yrvtrbkshXFjkqLedHieUnPioczy9wzdnzquHC'
      The status should be success
      The stderr should equal ""
    End
  End
  Describe '-t ipfs -k username password:'
    It 'prints ipfs keys for user "username" with password "password"'
      When run keygen -t ipfs -k username password
      The output should include '12D3KooWDMhdm5yrvtrbkshXFjkqLedHieUnPioczy9wzdnzquHC'
      The output should include 'CAESQA+XqCWjRqCjNe9oU3QA796bEH+T+rxgyPQ/EkXvE2MvNJoTbvcP+m51+XwxrmWqHaOpI1ZD0USwLjqAmV8Boas='
      The status should be success
      The stderr should equal ""
    End
  End
  Describe '-t ipfs -pk username password:'
    It 'prints prefixed ipfs keys for user "username" with password "password"'
      When run keygen -t ipfs -pk username password
      The output should include 'PeerID: 12D3KooWDMhdm5yrvtrbkshXFjkqLedHieUnPioczy9wzdnzquHC'
      The output should include 'PrivKEY: CAESQA+XqCWjRqCjNe9oU3QA796bEH+T+rxgyPQ/EkXvE2MvNJoTbvcP+m51+XwxrmWqHaOpI1ZD0USwLjqAmV8Boas='
      The status should be success
      The stderr should equal ""
    End
  End
  Describe '-t base64 -pk username password:'
    It 'prints prefixed base64 keys for user "username" with password "password"'
      When run keygen -t base64 -pk username password
      The output should include 'pub: NJoTbvcP+m51+XwxrmWqHaOpI1ZD0USwLjqAmV8Boas='
      The output should include 'sec: D5eoJaNGoKM172hTdADv3psQf5P6vGDI9D8SRe8TYy80mhNu9w/6bnX5fDGuZaodo6kjVkPRRLAuOoCZXwGhqw=='
      The status should be success
      The stderr should equal ""
    End
  End
  Describe "-o ${IPFS_PEM_FILE} -t ipfs username password:"
    It 'writes ipfs keys to file for user "username" with password "password"'
      When run keygen username password -o "${IPFS_PEM_FILE}" -t ipfs
      The path "${IPFS_PEM_FILE}" should exist
      The contents of file "${IPFS_PEM_FILE}" should include '-----BEGIN PRIVATE KEY-----'
      The contents of file "${IPFS_PEM_FILE}" should include 'MC4CAQAwBQYDK2VwBCIEIA+XqCWjRqCjNe9oU3QA796bEH+T+rxgyPQ/EkXvE2Mv'
      The contents of file "${IPFS_PEM_FILE}" should include '-----END PRIVATE KEY-----'
      The status should be success
      The stderr should equal ""
    End
    rm -f "${IPFS_PEM_FILE}"
  End
  Describe '-t pgp username password birthday:'
    gpg --batch --import --quiet specs/username.asc
    gpg --batch --import --quiet specs/username_protected.asc
    It 'creates a password protected gpg key for user username'
      Skip "You should implement it !"
      When run keygen -t pgp username password birthday
      The status should be success
    End
  End
  Describe '-g -t duniter -pk username:'
    It 'prints prefixed duniter keys for gpg key matching "username"'
      When run keygen -g -t duniter -pk username
      The output should include 'pub: 2g5UL2zhkn5i7oNYDpWo3fBuWvRYVU1AbMtdVmnGzPNv'
      The output should include 'sec: 5WtYFfA26nTfG496gAKhkrLYUMMnwXexmE1E8Q7PvtQEyscHfirsdMzW34zDp7WEkt3exNEVwoG4ajZYrm62wpi2'
      The status should be success
      The stderr should equal ""
    End
  End
  Describe '-g -t duniter -pk username@protected password:'
    It 'prints prefixed duniter keys for gpg key matching "username@protected" locked with "password"'
      When run keygen -g -t duniter -pk username@protected password
      The output should include 'pub: C1cRu7yb5rZhsmRHQkeZxusAhtYYJypcnXpY3HycEKsU'
      The output should include 'sec: VWaEdDroSCoagJDsBnDNUtXJtKAJYdqL6XKNiomz8DtiyF44FvpiMmhidXt2j8HhDBKPZ67xBGcZPnj4Myk6cB8'
      The status should be success
      The stderr should equal ""
    End
  End
  Describe '-g -t ipfs -pk username:'
    It 'prints prefixed ipfs keys for gpg key matching "username"'
      When run keygen -g -t ipfs -pk username
      The output should include 'PeerID: 12D3KooWBVSe5AaQwgMCXgsxrRG8pTGk1FUBXA5eYxFeskwAtL6r'
      The output should include 'PrivKEY: CAESQOHXwPgzoiDca1ZnvhU/W3zdogZXulkoErnUsqt+ut82GN5k4MIbVvz2m6Vq0ij9fQFPNUz+ZZdv2D31K6mzBQc='
      The status should be success
      The stderr should equal ""
    End
  End
  Describe '-g -t ipfs -pk username@protected password:'
    It 'prints prefixed ipfs keys for gpg key matching "username@protected" locked with "password"'
      When run keygen -g -t ipfs -pk username@protected password
      The output should include 'PeerID: 12D3KooWLpybeFZJGkqCHevi3MPujhx1CDbBLfu6k8BZRH8W8GbQ'
      The output should include 'PrivKEY: CAESQBiV+XnBNnryoeBs6SNj9e7Cd9Xj6INn24wyxxacylYqo5idwBHJto4Vbbp6NQzuUF+e7aCmrCf6y+BSyL42/i8='
      The status should be success
      The stderr should equal ""
    End
  End
  Describe "-g -o ${DUNITER_PUBSEC_FILE} -t duniter username:"
    It 'writes duniter keys to file for gpg key matching "username"'
      When run keygen -g -o "${DUNITER_PUBSEC_FILE}" -t duniter username
      The path "${DUNITER_PUBSEC_FILE}" should exist
      The contents of file "${DUNITER_PUBSEC_FILE}" should include 'pub: 2g5UL2zhkn5i7oNYDpWo3fBuWvRYVU1AbMtdVmnGzPNv'
      The contents of file "${DUNITER_PUBSEC_FILE}" should include 'sec: 5WtYFfA26nTfG496gAKhkrLYUMMnwXexmE1E8Q7PvtQEyscHfirsdMzW34zDp7WEkt3exNEVwoG4ajZYrm62wpi2'
      The status should be success
      The stderr should equal ""
    End
    rm -f "${DUNITER_PUBSEC_FILE}"
  End
  Describe "-g -o ${DUNITER_PUBSEC_FILE} -t duniter username@protected password:"
    It 'writes duniter keys to file for gpg key matching "username@protected" locked with "password"'
      When run keygen -g -o "${DUNITER_PUBSEC_FILE}" -t duniter username@protected password
      The path "${DUNITER_PUBSEC_FILE}" should exist
      The contents of file "${DUNITER_PUBSEC_FILE}" should include 'pub: C1cRu7yb5rZhsmRHQkeZxusAhtYYJypcnXpY3HycEKsU'
      The contents of file "${DUNITER_PUBSEC_FILE}" should include 'sec: VWaEdDroSCoagJDsBnDNUtXJtKAJYdqL6XKNiomz8DtiyF44FvpiMmhidXt2j8HhDBKPZ67xBGcZPnj4Myk6cB8'
      The status should be success
      The stderr should equal ""
    End
    rm -f "${DUNITER_PUBSEC_FILE}"
  End
  Describe "-g -o ${IPFS_PEM_FILE} -t ipfs username:"
    It 'writes ipfs keys to file for gpg key matching "username"'
      When run keygen -g -o "${IPFS_PEM_FILE}" -t ipfs username
      The path "${IPFS_PEM_FILE}" should exist
      The contents of file "${IPFS_PEM_FILE}" should include '-----BEGIN PRIVATE KEY-----'
      The contents of file "${IPFS_PEM_FILE}" should include 'MC4CAQAwBQYDK2VwBCIEIOHXwPgzoiDca1ZnvhU/W3zdogZXulkoErnUsqt+ut82'
      The contents of file "${IPFS_PEM_FILE}" should include '-----END PRIVATE KEY-----'
      The status should be success
      The stderr should equal ""
    End
    rm -f "${IPFS_PEM_FILE}"
  End
  Describe "-g -o ${IPFS_PEM_FILE} -t ipfs username@protected password:"
    It 'writes ipfs keys to file for gpg key matching "username@protected" locked with "password"'
      When run keygen -g -o "${IPFS_PEM_FILE}" -t ipfs username@protected password
      The path "${IPFS_PEM_FILE}" should exist
      The contents of file "${IPFS_PEM_FILE}" should include '-----BEGIN PRIVATE KEY-----'
      The contents of file "${IPFS_PEM_FILE}" should include 'MC4CAQAwBQYDK2VwBCIEIBiV+XnBNnryoeBs6SNj9e7Cd9Xj6INn24wyxxacylYq'
      The contents of file "${IPFS_PEM_FILE}" should include '-----END PRIVATE KEY-----'
      The status should be success
      The stderr should equal ""
    End
    rm -f "${IPFS_PEM_FILE}"
  End
  gpg --batch --delete-secret-and-public-key --yes 4D1CDB77E91FFCD81B10F9A7079E5BF4721944FB
  gpg --batch --delete-secret-and-public-key --yes 6AF574897D4979B7956AC31B6222A29CBC31A087
End

rm -rf "${TEST_DIR}"
