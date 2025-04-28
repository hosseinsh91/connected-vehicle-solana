#!/bin/bash

# Config
FROM_WALLET=~/.config/solana/id.json
VEHICLE_FOLDER="./vehicle_wallets"
AMOUNT="1"

# Loop from veh3 to veh100
for i in $(seq 3 100); do
    VEH_FILE="$VEHICLE_FOLDER/veh${i}_keypair.json"

    if [ -f "$VEH_FILE" ]; then
        # Extract wallet address
        ADDRESS=$(solana address -k "$VEH_FILE")

        echo "🚗 Sending 1 SOL to veh${i} ($ADDRESS)..."

        # Send 1 SOL
        solana transfer "$ADDRESS" "$AMOUNT" \
            --from "$FROM_WALLET" \
            --allow-unfunded-recipient \
            --fee-payer "$FROM_WALLET"

        echo "✅ Sent to veh${i}"
    else
        echo "⚠️ File not found: $VEH_FILE"
    fi
done
