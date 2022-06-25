#shellcheck shell=sh
set -eu

keygen() {
  if [ -x ./keygen ]; then
    ./keygen "$@"
  elif [ -x ./bin/keygen ]; then
    ./bin/keygen "$@"
  else
    keygen "$@"
  fi
}

Describe 'Dependency'
  Describe 'python3:'
    It 'is available'
      When run python3 --help
      The output should include "python3"
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
      The output should include 'v0.0.1'
      The status should be success
      The stderr should equal ""
    End
  End
  Describe '-t duniter username password:'
    It 'prints duniter keys for user username'
      When run keygen -t duniter username password
      The output should include 'pub: 4YLU1xQ9jzb7LzC6d91VZrYTEKS9N2j93Nnvcee6wxZG'
      The output should include 'sec: K5heSX4xGUPtRbxcZh6zbgaKbDv8FeVc9JuSNWtUs7C1oGNKqv7kQJ3DHdouTPzoW4duKKnuLQK8LbHKfN9fkjC'
      The status should be success
      The stderr should equal ""
    End
  End
  Describe '-o /tmp/keygen_test_duniter.pubsec -t duniter username password:'
    rm -f /tmp/keygen_test_duniter.pubsec
    It 'writes duniter keys to file for user username'
      When run keygen -o /tmp/keygen_test_duniter.pubsec -t duniter username password
      The path '/tmp/keygen_test_duniter.pubsec' should exist
      The contents of file '/tmp/keygen_test_duniter.pubsec' should include 'pub: 4YLU1xQ9jzb7LzC6d91VZrYTEKS9N2j93Nnvcee6wxZG'
      The contents of file '/tmp/keygen_test_duniter.pubsec' should include 'sec: K5heSX4xGUPtRbxcZh6zbgaKbDv8FeVc9JuSNWtUs7C1oGNKqv7kQJ3DHdouTPzoW4duKKnuLQK8LbHKfN9fkjC'
      The status should be success
      The stderr should equal ""
    End
  End
  Describe '-i /tmp/keygen_test_duniter.pubsec -t ipfs:'
    It 'prints ipfs keys for duniter keys read in pubsec file'
      When run keygen -i /tmp/keygen_test_duniter.pubsec -t ipfs
      The output should include 'PeerID: 12D3KooWDMhdm5yrvtrbkshXFjkqLedHieUnPioczy9wzdnzquHC'
      The output should include 'PrivKEY: CAESQA+XqCWjRqCjNe9oU3QA796bEH+T+rxgyPQ/EkXvE2MvNJoTbvcP+m51+XwxrmWqHaOpI1ZD0USwLjqAmV8Boas='
      The status should be success
      The stderr should equal ""
    End
  End
  Describe '-i /tmp/keygen_test_duniter.pubsec -o /tmp/keygen_test_ipfs.pem -t ipfs:'
    It 'writes ipfs keys to file for duniter keys read in pubsec file'
      When run keygen -i /tmp/keygen_test_duniter.pubsec -o /tmp/keygen_test_ipfs.pem -t ipfs
      The path '/tmp/keygen_test_ipfs.pem' should exist
      The contents of file '/tmp/keygen_test_ipfs.pem' should include '-----BEGIN PRIVATE KEY-----'
      The contents of file '/tmp/keygen_test_ipfs.pem' should include 'MC4CAQAwBQYDK2VwBCIEIA+XqCWjRqCjNe9oU3QA796bEH+T+rxgyPQ/EkXvE2Mv'
      The contents of file '/tmp/keygen_test_ipfs.pem' should include '-----END PRIVATE KEY-----'
      The status should be success
      The stderr should equal ""
    End
    rm -f /tmp/keygen_test_duniter.pubsec /tmp/keygen_test_ipfs.pem
  End
  Describe '-t ipfs username password:'
    It 'prints ipfs keys for user username'
      When run keygen -t ipfs username password
      The output should include 'PeerID: 12D3KooWDMhdm5yrvtrbkshXFjkqLedHieUnPioczy9wzdnzquHC'
      The output should include 'PrivKEY: CAESQA+XqCWjRqCjNe9oU3QA796bEH+T+rxgyPQ/EkXvE2MvNJoTbvcP+m51+XwxrmWqHaOpI1ZD0USwLjqAmV8Boas='
      The status should be success
      The stderr should equal ""
    End
  End
  Describe '-o /tmp/keygen_test_ipfs.pem -t ipfs username password:'
    It 'writes ipfs keys to file for user username'
      When run keygen username password -o /tmp/keygen_test_ipfs.pem -t ipfs
      The path '/tmp/keygen_test_ipfs.pem' should exist
      The contents of file '/tmp/keygen_test_ipfs.pem' should include '-----BEGIN PRIVATE KEY-----'
      The contents of file '/tmp/keygen_test_ipfs.pem' should include 'MC4CAQAwBQYDK2VwBCIEIA+XqCWjRqCjNe9oU3QA796bEH+T+rxgyPQ/EkXvE2Mv'
      The contents of file '/tmp/keygen_test_ipfs.pem' should include '-----END PRIVATE KEY-----'
      The status should be success
      The stderr should equal ""
    End
    rm -f /tmp/keygen_test_ipfs.pem
  End
  Describe '-t pgp username password birthday:'
    gpg --import --quiet specs/username.asc
    gpg --import --quiet specs/username.pub
    It 'creates a gpg key for user username'
      Skip "You should implement it !"
      When run keygen -t pgp username password
      The status should be success
    End
  End
  Describe '-g -t duniter username:'
    It 'prints duniter keys for gpg key matching username'
      When run keygen -g -t duniter username
      The output should include 'pub: 2g5UL2zhkn5i7oNYDpWo3fBuWvRYVU1AbMtdVmnGzPNv'
      The output should include 'sec: 5WtYFfA26nTfG496gAKhkrLYUMMnwXexmE1E8Q7PvtQEyscHfirsdMzW34zDp7WEkt3exNEVwoG4ajZYrm62wpi2'
      The status should be success
      The stderr should equal ""
    End
  End
  Describe '-g -t ipfs username:'
    It 'prints ipfs keys for gpg key matching username'
      When run keygen -g -t ipfs username
      The output should include 'PeerID: 12D3KooWBVSe5AaQwgMCXgsxrRG8pTGk1FUBXA5eYxFeskwAtL6r'
      The output should include 'PrivKEY: CAESQOHXwPgzoiDca1ZnvhU/W3zdogZXulkoErnUsqt+ut82GN5k4MIbVvz2m6Vq0ij9fQFPNUz+ZZdv2D31K6mzBQc='
      The status should be success
      The stderr should equal ""
    End
  End
  Describe '-g -o /tmp/keygen_test_duniter.pubsec -t duniter username:'
    It 'writes duniter keys to file for gpg key matching username'
      When run keygen -g -o /tmp/keygen_test_duniter.pubsec -t duniter username
      The path '/tmp/keygen_test_duniter.pubsec' should exist
      The contents of file '/tmp/keygen_test_duniter.pubsec' should include 'pub: 2g5UL2zhkn5i7oNYDpWo3fBuWvRYVU1AbMtdVmnGzPNv'
      The contents of file '/tmp/keygen_test_duniter.pubsec' should include 'sec: 5WtYFfA26nTfG496gAKhkrLYUMMnwXexmE1E8Q7PvtQEyscHfirsdMzW34zDp7WEkt3exNEVwoG4ajZYrm62wpi2'
      The status should be success
      The stderr should equal ""
    End
    rm -f /tmp/keygen_test_duniter.pubsec
  End
  Describe '-g -o /tmp/keygen_test_ipfs.pem -t ipfs username:'
    It 'writes ipfs keys to file for gpg key matching username'
      When run keygen -g -o /tmp/keygen_test_ipfs.pem -t ipfs username
      The path '/tmp/keygen_test_ipfs.pem' should exist
      The contents of file '/tmp/keygen_test_ipfs.pem' should include '-----BEGIN PRIVATE KEY-----'
      The contents of file '/tmp/keygen_test_ipfs.pem' should include 'MC4CAQAwBQYDK2VwBCIEIOHXwPgzoiDca1ZnvhU/W3zdogZXulkoErnUsqt+ut82'
      The contents of file '/tmp/keygen_test_ipfs.pem' should include '-----END PRIVATE KEY-----'
      The status should be success
      The stderr should equal ""
    End
    rm -f /tmp/keygen_test_ipfs.pem
  End
End
