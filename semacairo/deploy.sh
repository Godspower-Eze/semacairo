#!/bin/bash

# Array to store all verifier addresses
verifier_addresses=()

for i in {1..12}; do
    echo "======================================"
    echo "Declaring Semaphore_Groth16VerifierBN254_$i..."
    
    max_retries=5
    retry_count=0
    declare_success=false
    
    while [ $retry_count -lt $max_retries ]; do
        declare_output=$(sncast --account godspower declare --network sepolia --contract-name Semaphore_Groth16VerifierBN254_$i 2>&1)
        echo "$declare_output"
        
        if echo "$declare_output" | grep -q "cu limit exceeded"; then
            echo "RPC rate limit hit during declare. Sleeping for 20s and retrying..."
            sleep 20
            retry_count=$((retry_count+1))
            continue
        fi
        declare_success=true
        break
    done

    class_hash=$(echo "$declare_output" | grep -i "class hash:" | awk '{print $3}')
    
    if [ -z "$class_hash" ]; then
        echo "Trying to extract class hash from already declared error..."
        # Sometimes sncast says "Contract with class hash 0x... is already declared"
        class_hash=$(echo "$declare_output" | grep -oE "Contract with class hash 0x[0-9a-fA-F]+ is already declared" | awk '{print $5}')
        
        if [ -z "$class_hash" ]; then
             echo "Failed to extract class hash for verifier $i"
             exit 1
        fi
    fi
    
    echo "Waiting 30 seconds for class declaration to be indexed by Sepolia RPC..."
    sleep 30
    
    echo "Deploying Semaphore_Groth16VerifierBN254_$i with class hash $class_hash..."
    
    retry_count=0
    deploy_success=false
    while [ $retry_count -lt $max_retries ]; do
        deploy_output=$(sncast --account godspower deploy --network sepolia --class-hash "$class_hash" 2>&1)
        echo "$deploy_output"
        
        if echo "$deploy_output" | grep -q "cu limit exceeded"; then
            echo "RPC rate limit hit during deploy. Sleeping for 20s and retrying..."
            sleep 20
            retry_count=$((retry_count+1))
            continue
        fi
        
        # Check if it failed due to class not declared yet
        if echo "$deploy_output" | grep -q "is not declared"; then
            echo "Class not declared yet. Sleeping another 20s and retrying..."
            sleep 20
            retry_count=$((retry_count+1))
            continue
        fi
        
        deploy_success=true
        break
    done
    
    contract_address=$(echo "$deploy_output" | grep -i "contract address:" | awk '{print $3}')
    
    if [ -z "$contract_address" ]; then
        echo "Failed to deploy verifier $i"
        exit 1
    fi
    
    verifier_addresses+=("$contract_address")
done

echo "======================================="
echo "All 12 verifiers deployed successfully!"
echo "Addresses:"
printf '%s\n' "${verifier_addresses[@]}"
echo "======================================="

echo "Declaring Semaphore..."
semaphore_declare=$(sncast --account godspower declare --network sepolia --contract-name Semaphore 2>&1)
echo "$semaphore_declare"

semaphore_class=$(echo "$semaphore_declare" | grep -i "class hash:" | awk '{print $3}')
if [ -z "$semaphore_class" ]; then
    semaphore_class=$(echo "$semaphore_declare" | grep -oE "Contract with class hash 0x[0-9a-fA-F]+ is already declared" | awk '{print $5}')
    if [ -z "$semaphore_class" ]; then
        echo "Failed to extract class hash for Semaphore"
        exit 1
    fi
fi

echo "Waiting 30 seconds for Semaphore class declaration to be indexed by Sepolia RPC..."
sleep 30

echo "Deploying Semaphore..."

echo sncast --account godspower deploy --network sepolia --class-hash "$semaphore_class" --constructor-calldata 12 "${verifier_addresses[@]}"
final_deploy=$(sncast --account godspower deploy --network sepolia --class-hash "$semaphore_class" --constructor-calldata 12 "${verifier_addresses[@]}" 2>&1)
echo "$final_deploy"

semaphore_address=$(echo "$final_deploy" | grep -i "contract address:" | awk '{print $3}')

if [ -z "$semaphore_address" ]; then
    echo "Failed to deploy Semaphore"
    exit 1
fi

echo "======================================="
echo "Deployment successful!"
echo "Semaphore contract address: $semaphore_address"
