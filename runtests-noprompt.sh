#!/bin/bash

# same as runtests.sh but ignores all test which prompt user

stack test --test-arguments "-p !**/*_prompt*"
