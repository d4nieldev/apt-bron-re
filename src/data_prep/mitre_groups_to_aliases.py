import requests
from bs4 import BeautifulSoup
import json
from pathlib import Path

"""
This script adds MITRE_aliases to each group in data/layers_nodes/group.json,
by scraping the aliases from https://attack.mitre.org/groups/
"""

# Load group.json
group_path = Path("data/layers_nodes/group.json")
with group_path.open(encoding="utf-8") as f:
    group_data = json.load(f)

# Scrape aliases from MITRE ATT&CK website
url = "https://attack.mitre.org/groups/"
response = requests.get(url)
soup = BeautifulSoup(response.text, "html.parser")

group_table = soup.find("table")
rows = group_table.find_all("tr")[1:]  # skip header

# Map scraped group names to their aliases
alias_map = {}
for row in rows:
    cols = row.find_all("td")
    if len(cols) < 3:
        continue
    name = cols[1].text.strip()
    alias_string = cols[2].text.strip()
    aliases = [alias.strip() for alias in alias_string.split(",")] if alias_string else []
    alias_map[name] = aliases

# Inject aliases into group_data if name matches
for entry in group_data:
    group_name = entry.get("name")
    if group_name in alias_map:
        entry["MITRE_aliases"] = alias_map[group_name]

# Overwrite group.json with updated entries
with group_path.open("w", encoding="utf-8") as f:
    json.dump(group_data, f, indent=2, ensure_ascii=False)

print(f"Updated group.json with MITRE_aliases for matching entries.")
