#!/bin/bash

cargo run --example send_sms -- -m "hello!" \
      --system-id test_system \
      --password password \
      --to 123456789 \
      --from 123456789 \
      --host localhost \
      -p 2775
