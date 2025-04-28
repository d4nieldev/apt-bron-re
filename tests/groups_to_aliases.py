import requests
from bs4 import BeautifulSoup
import json
from pathlib import Path

"""
This script creates a mapping between groups and their aliases
as disclosed in https://attack.mitre.org/groups/
it stores the output under data/group_aliases_results/group_to_aliases_mapping.json
"""

url = "https://attack.mitre.org/groups/"
response = requests.get(url)
soup = BeautifulSoup(response.text, "html.parser")

group_table = soup.find("table")
rows = group_table.find_all("tr")[1:]  # skip header

group_aliases = {}

for row in rows:
    cols = row.find_all("td")
    if len(cols) < 3:
        continue

    group_name = cols[1].text.strip()
    aliases_raw = cols[2].text.strip()
    aliases = [
        alias.strip() for alias in aliases_raw.split(",")
        if (alias.strip().lower() != "tick" and alias.strip().lower() != "chromium")
    ] if aliases_raw else []
    group_aliases[group_name] = aliases

# Save to data/group_to_aliases_mapping.json
output_path = Path("data/group_aliases_results/group_to_aliases_mapping.json")
output_path.parent.mkdir(parents=True, exist_ok=True)

with open(output_path, "w", encoding="utf-8") as f:
    json.dump(group_aliases, f, indent=2, ensure_ascii=False)

print(f"Done. Saved to {output_path}")
