#!/bin/bash

# First (optional) parameter is the 'stack.yaml' file.
if [ -z "$1" ]; then
  stack_yaml="stack.yaml"
else
  stack_yaml="$1"
fi

# Run setup again, just in case. This will already have run in actual build.
# This duplicate 'setup' is for testing the tests outside of CI.
docker-compose run --rm tests stack --stack-yaml "$stack_yaml" setup

# Wrapper to run tests without prompts on CI
docker-compose run --rm tests stack --stack-yaml "$stack_yaml" test --test-arguments="-p !**/*no_ci"
