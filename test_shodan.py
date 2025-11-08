# test_shodan.py
from orbitduck.modules.shodan_search import shodan_host_lookup

# Replace with a known IP for testing
target_ip = "8.8.8.8"

result = shodan_host_lookup(target_ip)

print("Shodan lookup result:")
print(result)