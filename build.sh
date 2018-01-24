#!/bin/bash

echo "Cleaning..."
rm -rf ./bin

echo "Compiling linux binary..."
GOOS=linux GOARCH=amd64 go build -o bin/linux-64

echo "Compiling windows binary..."
GOOS=windows GOARCH=amd64 go build -o bin/windows-64.exe

echo "Compiling osx binary..."
go build -o bin/darwin-64
