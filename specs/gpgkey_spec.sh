#shellcheck shell=sh
set -eu

gpgkey() {
  if [ -x ./gpgkey ]; then
    ./gpgkey "$@"
  elif [ -x ./bin/gpgkey ]; then
    ./bin/gpgkey "$@"
  else
    gpgkey "$@"
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

Describe 'gpgkey'
  Describe '--help:'
    It 'prints help'
      When run gpgkey --help
      The output should include 'usage:'
      The status should be success
      The stderr should equal ""
    End
  End
  Describe '--version:'
    It 'prints version'
      When run gpgkey --version
      The output should include 'v0.0.1'
      The status should be success
      The stderr should equal ""
    End
  End
  Describe 'duniter username password:'
    It 'prints duniter keys for user username'
      When run gpgkey duniter username password
      The output should include 'pub: 4YLU1xQ9jzb7LzC6d91VZrYTEKS9N2j93Nnvcee6wxZG'
      The output should include 'sec: K5heSX4xGUPtRbxcZh6zbgaKbDv8FeVc9JuSNWtUs7C1oGNKqv7kQJ3DHdouTPzoW4duKKnuLQK8LbHKfN9fkjC'
      The status should be success
      The stderr should equal ""
    End
  End
  Describe 'duniter username password -o /tmp/test_gpgkey_duniter.pubsec:'
    rm -f /tmp/test_gpgkey_duniter.pubsec
    It 'writes duniter keys to file for user username'
      When run gpgkey duniter username password -o /tmp/test_gpgkey_duniter.pubsec
      The path '/tmp/test_gpgkey_duniter.pubsec' should exist
      The contents of file '/tmp/test_gpgkey_duniter.pubsec' should include 'pub: 4YLU1xQ9jzb7LzC6d91VZrYTEKS9N2j93Nnvcee6wxZG'
      The contents of file '/tmp/test_gpgkey_duniter.pubsec' should include 'sec: K5heSX4xGUPtRbxcZh6zbgaKbDv8FeVc9JuSNWtUs7C1oGNKqv7kQJ3DHdouTPzoW4duKKnuLQK8LbHKfN9fkjC'
      The status should be success
      The stderr should equal ""
    End
  End
  Describe 'ipfs -i /tmp/test_gpgkey_duniter.pubsec:'
    It 'prints ipfs keys for duniter keys read in pubsec file'
      When run gpgkey ipfs -i /tmp/test_gpgkey_duniter.pubsec
      The output should include 'PeerID: 12D3KooWDMhdm5yrvtrbkshXFjkqLedHieUnPioczy9wzdnzquHC'
      The output should include 'PrivKEY: CAESQA+XqCWjRqCjNe9oU3QA796bEH+T+rxgyPQ/EkXvE2MvNJoTbvcP+m51+XwxrmWqHaOpI1ZD0USwLjqAmV8Boas='
      The status should be success
      The stderr should equal ""
    End
  End
  Describe 'ipfs -i /tmp/test_gpgkey_duniter.pubsec -o /tmp/test_gpgkey_ipfs.pubsec:'
    It 'writes duniter and ipfs keys to file for duniter keys read in pubsec file'
      When run gpgkey ipfs -i /tmp/test_gpgkey_duniter.pubsec -o /tmp/test_gpgkey_ipfs.pubsec
      The path '/tmp/test_gpgkey_ipfs.pubsec' should exist
      The contents of file '/tmp/test_gpgkey_ipfs.pubsec' should include 'pub: 4YLU1xQ9jzb7LzC6d91VZrYTEKS9N2j93Nnvcee6wxZG'
      The contents of file '/tmp/test_gpgkey_ipfs.pubsec' should include 'sec: K5heSX4xGUPtRbxcZh6zbgaKbDv8FeVc9JuSNWtUs7C1oGNKqv7kQJ3DHdouTPzoW4duKKnuLQK8LbHKfN9fkjC'
      The contents of file '/tmp/test_gpgkey_ipfs.pubsec' should include 'PeerID: 12D3KooWDMhdm5yrvtrbkshXFjkqLedHieUnPioczy9wzdnzquHC'
      The contents of file '/tmp/test_gpgkey_ipfs.pubsec' should include 'PrivKEY: CAESQA+XqCWjRqCjNe9oU3QA796bEH+T+rxgyPQ/EkXvE2MvNJoTbvcP+m51+XwxrmWqHaOpI1ZD0USwLjqAmV8Boas='
      The status should be success
      The stderr should equal ""
    End
    rm -f /tmp/test_gpgkey_duniter.pubsec /tmp/test_gpgkey_ipfs.pubsec
  End
  Describe 'ipfs username password:'
    It 'prints ipfs keys for user username'
      When run gpgkey ipfs username password
      The output should include 'PeerID: 12D3KooWDMhdm5yrvtrbkshXFjkqLedHieUnPioczy9wzdnzquHC'
      The output should include 'PrivKEY: CAESQA+XqCWjRqCjNe9oU3QA796bEH+T+rxgyPQ/EkXvE2MvNJoTbvcP+m51+XwxrmWqHaOpI1ZD0USwLjqAmV8Boas='
      The status should be success
      The stderr should equal ""
    End
  End
  Describe 'ipfs username password -o /tmp/test_gpgkey_ipfs.pubsec:'
    It 'writes duniter and ipfs keys to file for user username'
      When run gpgkey ipfs username password -o /tmp/test_gpgkey_ipfs.pubsec
      The path '/tmp/test_gpgkey_ipfs.pubsec' should exist
      The contents of file '/tmp/test_gpgkey_ipfs.pubsec' should include 'pub: 4YLU1xQ9jzb7LzC6d91VZrYTEKS9N2j93Nnvcee6wxZG'
      The contents of file '/tmp/test_gpgkey_ipfs.pubsec' should include 'sec: K5heSX4xGUPtRbxcZh6zbgaKbDv8FeVc9JuSNWtUs7C1oGNKqv7kQJ3DHdouTPzoW4duKKnuLQK8LbHKfN9fkjC'
      The contents of file '/tmp/test_gpgkey_ipfs.pubsec' should include 'PeerID: 12D3KooWDMhdm5yrvtrbkshXFjkqLedHieUnPioczy9wzdnzquHC'
      The contents of file '/tmp/test_gpgkey_ipfs.pubsec' should include 'PrivKEY: CAESQA+XqCWjRqCjNe9oU3QA796bEH+T+rxgyPQ/EkXvE2MvNJoTbvcP+m51+XwxrmWqHaOpI1ZD0USwLjqAmV8Boas='
      The status should be success
      The stderr should equal ""
    End
    rm -f /tmp/test_gpgkey_ipfs.pubsec
  End
  Describe 'pgp username password:'
    gpg --import --quiet specs/username.asc
    gpg --import --quiet specs/username.pub
    It 'creates a gpg key for user username'
      Skip "You should implement it !"
      When run gpgkey --gen pgp username password
      The status should be success
    End
  End
  Describe 'pgp username password:'
    It 'prints duniter and ipfs keys for gpg key matching username'
      When run gpgkey pgp username password
      The output should include 'pub: 2g5UL2zhkn5i7oNYDpWo3fBuWvRYVU1AbMtdVmnGzPNv'
      The output should include 'sec: 5WtYFfA26nTfG496gAKhkrLYUMMnwXexmE1E8Q7PvtQEyscHfirsdMzW34zDp7WEkt3exNEVwoG4ajZYrm62wpi2'
      The output should include 'PeerID: 12D3KooWBVSe5AaQwgMCXgsxrRG8pTGk1FUBXA5eYxFeskwAtL6r'
      The output should include 'PrivKEY: CAESQOHXwPgzoiDca1ZnvhU/W3zdogZXulkoErnUsqt+ut82GN5k4MIbVvz2m6Vq0ij9fQFPNUz+ZZdv2D31K6mzBQc='
      The status should be success
      The stderr should equal ""
    End
  End
  Describe 'pgp username password -o /tmp/test_gpgkey_pgp.pubsec:'
    It 'writes duniter and ipfs keys to file for gpg key matching username'
      When run gpgkey pgp username password -o /tmp/test_gpgkey_pgp.pubsec
      The path '/tmp/test_gpgkey_pgp.pubsec' should exist
      The contents of file '/tmp/test_gpgkey_pgp.pubsec' should include 'pub: 2g5UL2zhkn5i7oNYDpWo3fBuWvRYVU1AbMtdVmnGzPNv'
      The contents of file '/tmp/test_gpgkey_pgp.pubsec' should include 'sec: 5WtYFfA26nTfG496gAKhkrLYUMMnwXexmE1E8Q7PvtQEyscHfirsdMzW34zDp7WEkt3exNEVwoG4ajZYrm62wpi2'
      The contents of file '/tmp/test_gpgkey_pgp.pubsec' should include 'PeerID: 12D3KooWBVSe5AaQwgMCXgsxrRG8pTGk1FUBXA5eYxFeskwAtL6r'
      The contents of file '/tmp/test_gpgkey_pgp.pubsec' should include 'PrivKEY: CAESQOHXwPgzoiDca1ZnvhU/W3zdogZXulkoErnUsqt+ut82GN5k4MIbVvz2m6Vq0ij9fQFPNUz+ZZdv2D31K6mzBQc='
      The status should be success
      The stderr should equal ""
    End
    rm -f /tmp/test_gpgkey_pgp.pubsec
  End
End
