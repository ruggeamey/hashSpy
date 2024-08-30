#!/bin/bash

# ANSI color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'  # No Color

# Function to check if a hash is salted based on format
check_salted() {
    local HASH="$1"
    
    # Check for known salted hash patterns
    if [[ $HASH =~ ^\$2[abyz]\$ ]]; then
        echo -e "${CYAN}This is a salted bcrypt hash.${NC}"
    elif [[ $HASH =~ ^{SSHA} ]]; then
        echo -e "${CYAN}This is a salted SSHA (Salted SHA-1) hash.${NC}"
    elif [[ $HASH =~ ^\$5\$ ]]; then
        echo -e "${CYAN}This is a salted SHA-256 (Unix Crypt) hash.${NC}"
    elif [[ $HASH =~ ^\$6\$ ]]; then
        echo -e "${CYAN}This is a salted SHA-512 (Unix Crypt) hash.${NC}"
    elif [[ $HASH =~ ^\$argon2 ]]; then
        echo -e "${CYAN}This is a salted Argon2 hash.${NC}"
    elif [[ $HASH =~ ^\$pbkdf2\$ ]]; then
        echo -e "${CYAN}This is a salted PBKDF2 hash.${NC}"
    elif [[ $HASH =~ ^[A-Za-z0-9+/=]{64}$ ]]; then
        echo -e "${CYAN}This may be a salted SSHA-256 hash.${NC}"
    elif [[ $HASH =~ ^[A-Za-z0-9+/=]{128}$ ]]; then
        echo -e "${CYAN}This may be a salted SSHA-512 hash.${NC}"
    else
        echo -e "${RED}This hash does not appear to be salted.${NC}"
    fi
}

# Function to identify the type of hash based on length and patterns
identify_hash() {
    local HASH="$1"
    local HASH_LEN="${#HASH}"

    case $HASH_LEN in
        8)
            echo -e "${GREEN}CRC32: 8 characters, usually hexadecimal.${NC}"
            ;;
        16)
            echo -e "${GREEN}NTLM/MD4 or LM Hash: 16 characters, hex encoded.${NC}"
            ;;
        32)
            if [[ $HASH =~ ^[0-9a-fA-F]{32}$ ]]; then
                echo -e "${GREEN}MD5: 32 characters, hex encoded.${NC}"
            elif [[ $HASH =~ ^[0-9a-fA-F]{32}$ ]]; then
                echo -e "${GREEN}NTLM: 32 characters, used in Windows systems.${NC}"
            fi
            ;;
        40)
            if [[ $HASH =~ ^[0-9a-fA-F]{40}$ ]]; then
                echo -e "${GREEN}SHA-1: 40 characters, hex encoded.${NC}"
            else
                echo -e "${YELLOW}Unrecognized 40-character hash.${NC}"
            fi
            ;;
        56)
            echo -e "${GREEN}SHA-224: 56 characters, hex encoded.${NC}"
            ;;
        64)
            if [[ $HASH =~ ^[0-9a-fA-F]{64}$ ]]; then
                echo -e "${GREEN}SHA-256: 64 characters, hex encoded.${NC}"
            elif [[ $HASH =~ ^[A-Za-z0-9+/=]{64}$ ]]; then
                echo -e "${GREEN}SSHA-256 (Salted SHA-256)${NC}"
            else
                echo -e "${YELLOW}Unknown 64-character hash format.${NC}"
            fi
            ;;
        96)
            echo -e "${GREEN}SHA-384: 96 characters, hex encoded.${NC}"
            ;;
        128)
            if [[ $HASH =~ ^[0-9a-fA-F]{128}$ ]]; then
                echo -e "${GREEN}SHA-512: 128 characters, hex encoded.${NC}"
            elif [[ $HASH =~ ^[A-Za-z0-9+/=]{128}$ ]]; then
                echo -e "${GREEN}SSHA-512 (Salted SHA-512)${NC}"
            else
                echo -e "${YELLOW}Unknown 128-character hash format.${NC}"
            fi
            ;;
        34)
            echo -e "${GREEN}CRC64: 34 characters.${NC}"
            ;;
        60)
            if [[ $HASH =~ ^\$2[abyz]\$.{56}$ ]]; then
                echo -e "${GREEN}bcrypt: Password hash scheme (Linux/Unix systems).${NC}"
            else
                echo -e "${YELLOW}Unrecognized 60-character hash format.${NC}"
            fi
            ;;
        88)
            if [[ $HASH =~ ^\$argon2 ]]; then
                echo -e "${GREEN}Argon2: Modern memory-hard password hashing algorithm.${NC}"
            fi
            ;;
        98)
            if [[ $HASH =~ ^\$pbkdf2 ]]; then
                echo -e "${GREEN}PBKDF2: Password-Based Key Derivation Function 2.${NC}"
            fi
            ;;
        *)
            if [[ $HASH =~ ^\$2[abyz]\$.{56}$ ]]; then
                echo -e "${GREEN}bcrypt: Password hash scheme (Linux/Unix systems).${NC}"
            elif [[ $HASH =~ ^{SSHA}[a-zA-Z0-9+/]{28,}==$ ]]; then
                echo -e "${GREEN}SSHA: Salted SHA-1.${NC}"
            elif [[ $HASH =~ ^\$5\$ ]]; then
                echo -e "${GREEN}SHA-256 (Unix Crypt Format).${NC}"
            elif [[ $HASH =~ ^\$6\$ ]]; then
                echo -e "${GREEN}SHA-512 (Unix Crypt Format).${NC}"
            else
                echo -e "${RED}Unrecognized or unsupported hash type.${NC}"
            fi
            ;;
    esac
}

# Interactive user input
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}       WELCOME TO HASH-SPY${NC}"
echo -e "${BLUE}========================================${NC}"
read -p "Please enter the hash string to identify: " HASH_INPUT
echo -e "${BLUE}========================================${NC}"

# Remove any whitespaces from the input
HASH_INPUT=$(echo "$HASH_INPUT" | tr -d '[:space:]')

# Identify the hash type
identify_hash "$HASH_INPUT"

# Check if the hash is salted
echo -e "${BLUE}----------------------------------------${NC}"
check_salted "$HASH_INPUT"
