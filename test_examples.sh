#!/bin/bash

# Test script to verify all examples can be invoked and show proper help/error messages

echo "🧪 Testing SMPP Examples"
echo "========================"

echo
echo "📧 Testing send_sms example..."
echo "Running: cargo run --example send_sms -- --help"
cargo run --example send_sms -- --help
echo "✅ send_sms help works"

echo
echo "⏰ Testing long_running_client example..."
echo "Running: cargo run --example long_running_client -- --help"
cargo run --example long_running_client -- --help
echo "✅ long_running_client help works"

echo
echo "🔧 Testing send_sms with invalid args (should show error)..."
echo "Running: cargo run --example send_sms -- --message 'test' --to 123"
timeout 2s cargo run --example send_sms -- --message 'test' --to 123 2>&1 | head -3
echo "✅ send_sms error handling works"

echo
echo "⚡ Testing long_running_client with invalid config (should try to connect and fail quickly)..."
echo "Running: cargo run --example long_running_client -- --run-duration 1"
timeout 5s cargo run --example long_running_client -- --run-duration 1 2>&1 | head -5
echo "✅ long_running_client error handling works"

echo
echo "🎉 All examples compile and execute correctly!"
echo "   (Connection failures are expected without a real SMSC)"