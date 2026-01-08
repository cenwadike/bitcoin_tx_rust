#!/bin/bash
# Bitcoin Core Integration Script for Testing Rust Transactions

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Bitcoin Core Integration Test ===${NC}\n"

# Check if bitcoin-cli is available
if ! command -v bitcoin-cli &> /dev/null; then
    echo -e "${RED}Error: bitcoin-cli not found. Please install Bitcoin Core.${NC}"
    exit 1
fi

# Configuration
BITCOIN_CLI="bitcoin-cli -regtest"
DATADIR="${HOME}/.bitcoin/regtest"

echo -e "${YELLOW}Step 1: Starting Bitcoin Core in regtest mode...${NC}"
bitcoind -regtest -daemon -fallbackfee=0.00001 -txindex=1
sleep 3

# Create wallet if it doesn't exist
echo -e "${YELLOW}Step 2: Creating wallet...${NC}"
$BITCOIN_CLI createwallet "testwallet" 2>/dev/null || echo "Wallet already exists"
$BITCOIN_CLI loadwallet "testwallet" 2>/dev/null || true

# Generate blocks to get coins
echo -e "${YELLOW}Step 3: Generating 101 blocks...${NC}"
ADDRESS=$($BITCOIN_CLI getnewaddress)
$BITCOIN_CLI generatetoaddress 101 $ADDRESS > /dev/null
echo -e "${GREEN}✓ Generated 101 blocks${NC}"

# Test 1: P2WPKH Transaction
echo -e "\n${YELLOW}Test 1: P2WPKH Single Input Transaction${NC}"
echo "----------------------------------------"

# Fund a P2WPKH address from Rust
TEST_ADDRESS="bcrt1ql3e9pgs3mmwuwrh95fecme0s0qtn2880hlwwpw"
echo "Funding address: $TEST_ADDRESS"
TXID=$($BITCOIN_CLI sendtoaddress $TEST_ADDRESS 2.001)
echo "Funding txid: $TXID"

# Mine a block to confirm
$BITCOIN_CLI generatetoaddress 1 $ADDRESS > /dev/null
echo -e "${GREEN}✓ Transaction confirmed${NC}"

# Get the transaction details (use gettransaction for wallet transactions)
echo -e "\n${GREEN}Transaction Details:${NC}"
$BITCOIN_CLI gettransaction $TXID | grep -E '"amount"|"confirmations"|"blockhash"' || true

# Get the raw transaction and decode it
echo -e "\n${GREEN}Finding your UTXO:${NC}"
RAW_TX=$($BITCOIN_CLI getrawtransaction $TXID)
DECODED=$($BITCOIN_CLI decoderawtransaction $RAW_TX)

# Find the vout index for our address
VOUT_INDEX=$(echo "$DECODED" | grep -A 20 '"vout"' | grep -B 5 "$TEST_ADDRESS" | grep '"n"' | head -1 | grep -o '[0-9]*')

if [ ! -z "$VOUT_INDEX" ]; then
    echo -e "${GREEN}✓ Found UTXO at vout index: $VOUT_INDEX${NC}"
    echo -e "${GREEN}  TXID: $TXID${NC}"
    echo -e "${GREEN}  Amount: 2.001 BTC${NC}"
else
    echo -e "${YELLOW}Could not automatically find vout index. Check manually:${NC}"
    echo "  $BITCOIN_CLI getrawtransaction $TXID true"
fi

echo -e "\n${GREEN}Next Steps:${NC}"
echo "1. Use TXID: $TXID"
echo "2. Use vout index: $VOUT_INDEX (or check manually)"
echo "3. Create transaction in Rust with these values"
echo "4. Broadcast your signed tx with:"
echo "   $BITCOIN_CLI sendrawtransaction <hex>"

# Show how to get raw transaction
echo -e "\n${GREEN}To get raw transaction:${NC}"
echo "  $BITCOIN_CLI getrawtransaction $TXID"

# Show how to decode transaction
echo -e "\n${GREEN}To decode transaction:${NC}"
echo "  RAW=\$($BITCOIN_CLI getrawtransaction $TXID)"
echo "  $BITCOIN_CLI decoderawtransaction \$RAW"

# Test 2: Decode and Verify
echo -e "\n${YELLOW}Test 2: Transaction Verification${NC}"
echo "-----------------------------------"
echo "To verify a transaction before broadcasting:"
echo "  $BITCOIN_CLI testmempoolaccept '[\"<your_hex>\"]'"
echo ""
echo "To decode your signed transaction:"
echo "  $BITCOIN_CLI decoderawtransaction <your_hex>"

# Test 3: P2WSH Multisig Setup
echo -e "\n${YELLOW}Test 3: P2WSH Multisig Address${NC}"
echo "-------------------------------"
echo "Create multisig address with Rust, then fund it:"
P2WSH_EXAMPLE="bcrt1qpqn5k3h89nfv6cnrkvk3rt3g0zfhqfz23cxkgapsenj29ety5ckqyrn25s"
echo "Example P2WSH address: $P2WSH_EXAMPLE"
echo "To fund: $BITCOIN_CLI sendtoaddress $P2WSH_EXAMPLE 2.001"

# Show current balance
echo -e "\n${GREEN}Current Wallet Balance:${NC}"
$BITCOIN_CLI getbalance

# Show available UTXOs
echo -e "\n${GREEN}Available UTXOs:${NC}"
$BITCOIN_CLI listunspent | grep -E '"txid"|"vout"|"amount"|"address"' | head -20

# Cleanup function
cleanup() {
    echo -e "\n${YELLOW}Cleaning up...${NC}"
    $BITCOIN_CLI stop 2>/dev/null || true
    sleep 2
    echo -e "${GREEN}✓ Bitcoin Core stopped${NC}"
}

# Ask user if they want to keep Bitcoin Core running
echo -e "\n${YELLOW}Do you want to keep Bitcoin Core running? (y/n)${NC}"
read -t 30 -p "> " KEEP_RUNNING || KEEP_RUNNING="n"

if [ "$KEEP_RUNNING" != "y" ]; then
    cleanup
else
    echo -e "${GREEN}Bitcoin Core is still running. Stop it with: $BITCOIN_CLI stop${NC}"
    echo -e "${YELLOW}Useful commands while it's running:${NC}"
    echo "  $BITCOIN_CLI getblockcount          # Check block height"
    echo "  $BITCOIN_CLI getbalance             # Check balance"
    echo "  $BITCOIN_CLI listunspent            # List UTXOs"
    echo "  $BITCOIN_CLI getnewaddress          # Get new address"
    echo "  $BITCOIN_CLI generatetoaddress 1 \$($BITCOIN_CLI getnewaddress)  # Mine a block"
fi

echo -e "\n${GREEN}=== Integration test setup complete! ===${NC}"
echo -e "\n${YELLOW}Quick Reference:${NC}"
echo "Funded address: $TEST_ADDRESS"
echo "Funding TXID: $TXID"
if [ ! -z "$VOUT_INDEX" ]; then
    echo "VOUT index: $VOUT_INDEX"
fi
echo ""
echo -e "${GREEN}Ready to create transactions in Rust!${NC}"