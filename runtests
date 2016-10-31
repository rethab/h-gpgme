#!/bin/bash

echo "Saving passphrases in gpg-agent"
eval $(gpg-agent --daemon)
echo 'Use `pkill -SIGHUP gpg-agent` to clear cached passphrases'
echo "Bob's passphrase: \`bob123\`"
echo "Alice's passphrase: \`alice123\`"
echo "Use any password for symmetrical encryption test"

# Remove this annoying file if it already exists
rm -f tests.tix

if [ -z "$@" ]; then
  stack test
else
  echo "Running with the test arguments '-p $@'"
  stack test --test-arguments "-p $@"
fi
