#!/bin/bash

# Function to print colored text
print_colored() {
  echo -e "\033[1;36m$1\033[0m"
}

# Compile all Java files
compile_app() {
  print_colored "=== Compiling Secure Chat Application ==="
  javac -d . $(find . -name "*.java")
  if [ $? -eq 0 ]; then
    print_colored "Compilation successful!"
  else
    echo "Compilation failed!"
    exit 1
  fi
}

# Run the server
run_server() {
  print_colored "=== Starting Chat Server ==="
  java Chat.ChatServerMain
}

# Run the client
run_client() {
  print_colored "=== Starting Chat Client ==="
  java Chat.ChatClientMain
}

# Main menu
show_menu() {
  clear
  print_colored "=== Secure Chat Application ==="
  echo "1) Compile application"
  echo "2) Run server"
  echo "3) Run client"
  echo "4) Compile and run server"
  echo "5) Compile and run client"
  echo "6) Exit"
  echo ""
  read -p "Select an option: " choice
  
  case $choice in
    1) compile_app; show_menu ;;
    2) run_server ;;
    3) run_client ;;
    4) compile_app && run_server ;;
    5) compile_app && run_client ;;
    6) exit 0 ;;
    *) echo "Invalid option"; sleep 1; show_menu ;;
  esac
}

# Start the menu
cd "$(dirname "$0")"
show_menu
