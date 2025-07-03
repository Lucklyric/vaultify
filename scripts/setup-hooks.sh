#!/bin/bash
# Setup git hooks for the project

echo "Setting up git hooks..."

# Configure git to use our hooks directory
git config core.hooksPath .githooks

echo "✅ Git hooks configured! Pre-push checks will now run automatically."
echo "To disable: git config --unset core.hooksPath"