#!/bin/bash

# Generate inspection files in MD format for all primary contracts in src.

CONTRACT_FILES=($(find src -iname '*.sol' | sort))

rm .storagelayout.md
rm .gasestimates.md

echo "# Storage Layouts" >> .storagelayout.md
echo "Generated via \`bash utils/inspect.sh\`." >> .storagelayout.md
echo "" >> .storagelayout.md
echo "---" >> .storagelayout.md
echo "" >> .storagelayout.md

echo "# Gas Estimates" >> .gasestimates.md
echo "Generated via \`bash utils/inspect.sh\`." >> .gasestimates.md
echo "" >> .gasestimates.md
echo "---" >> .gasestimates.md
echo "" >> .gasestimates.md
echo "\`forge test --gas-report --no-match-path \"test/invariant/**/*\"\`" >> .gasestimates.md
# Sed strings to strip color data and only start printing after the first '|' character, to exclude previous contents (compilation, test results, etc)
forge test --gas-report --no-match-path "test/invariant/**/*" | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2};?)?)?[mGK]//g" | sed -nr '/\|/,$p' >> .gasestimates.md

for index in ${!CONTRACT_FILES[*]}; do
  # echo "${CONTRACT_NAMES[$index]} is in ${CONTRACT_FILES[$index]}"
  CONTRACT_NAME=$(basename -s ".sol" ${CONTRACT_FILES[${index}]})
  # echo ${CONTRACT_NAME}
  # If file does not contain a contract named the same as the filename, discard from inspection (e.g. libraries).
  if ! grep -q "contract ${CONTRACT_NAME}" ${CONTRACT_FILES[$index]}; then
    # echo "Skipping ${CONTRACT_NAME}"
    continue
  fi

  # Show command names in files
  echo "\`forge inspect --pretty ${CONTRACT_FILES[$index]}:${CONTRACT_NAME} storage-layout\`" >> .storagelayout.md
  forge inspect --pretty ${CONTRACT_FILES[$index]}:${CONTRACT_NAME} storage-layout >> .storagelayout.md
  echo "" >> .storagelayout.md

  # echo "\`forge inspect ${CONTRACT_FILES[$index]}:${CONTRACT_NAME} gasestimates\`" >> .gasestimates.md
  # echo "\`\`\`json" >> .gasestimates.md
  # forge inspect ${CONTRACT_FILES[$index]}:${CONTRACT_NAME} gasestimates >> .gasestimates.md
  # echo "\`\`\`" >> .gasestimates.md
  # echo "" >> .gasestimates.md

done
