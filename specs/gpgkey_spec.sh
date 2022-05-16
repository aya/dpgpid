#shellcheck shell=sh
set -eu

gpgkey() {
  ./gpgkey "$@"
}

Describe 'Dependency'
  Describe 'python3'
    It 'is available'
      When run which python3
      The output should include "/python3"
      The status should be success
      The stderr should equal ""
    End
  End
End

Describe 'gpgkey'
  Describe '--help'
    It 'prints help'
      When run gpgkey --help
      The output should include 'usage:'
      The status should be success
      The stderr should equal ""
    End
  End
  Describe '--version'
    It 'prints version'
      When run gpgkey --version
      The output should include 'v0.0.1'
      The status should be success
      The stderr should equal ""
    End
  End
  Describe 'duniter username password -o /tmp/test_gpgkey'
    rm -f /tmp/test_gpgkey
    It 'prints duniter public key and write duniter keys to file /tmp/test_gpgkey for user username'
      When run gpgkey duniter username password -o /tmp/test_gpgkey
      The output should eq '4YLU1xQ9jzb7LzC6d91VZrYTEKS9N2j93Nnvcee6wxZG'
      The path '/tmp/test_gpgkey' should exist
      The contents of file '/tmp/test_gpgkey' should include 'pub: 4YLU1xQ9jzb7LzC6d91VZrYTEKS9N2j93Nnvcee6wxZG'
      The contents of file '/tmp/test_gpgkey' should include 'sec: K5heSX4xGUPtRbxcZh6zbgaKbDv8FeVc9JuSNWtUs7C1oGNKqv7kQJ3DHdouTPzoW4duKKnuLQK8LbHKfN9fkjC'
      The status should be success
      The stderr should equal ""
    End
  End
  Describe 'ipfs -i /tmp/test_gpgkey'
    It 'prints ipfs PeerID and PrivKEY for duniter keys in file /tmp/test_gpgkey'
      When run gpgkey ipfs -i /tmp/test_gpgkey
      The output should include 'PeerID=12D3KooWDMhdm5yrvtrbkshXFjkqLedHieUnPioczy9wzdnzquHC'
      The output should include 'PrivKEY=CAESQA+XqCWjRqCjNe9oU3QA796bEH+T+rxgyPQ/EkXvE2MvNJoTbvcP+m51+XwxrmWqHaOpI1ZD0USwLjqAmV8Boas='
      The status should be success
      The stderr should equal ""
    End
    rm -f /tmp/test_gpgkey
  End
  Describe 'ipfs username password'
    It 'prints ipfs PeerID and PrivKEY for user username'
      When run gpgkey ipfs username password
      The output should include 'PeerID=12D3KooWDMhdm5yrvtrbkshXFjkqLedHieUnPioczy9wzdnzquHC'
      The output should include 'PrivKEY=CAESQA+XqCWjRqCjNe9oU3QA796bEH+T+rxgyPQ/EkXvE2MvNJoTbvcP+m51+XwxrmWqHaOpI1ZD0USwLjqAmV8Boas='
      The status should be success
      The stderr should equal ""
    End
  End
End
