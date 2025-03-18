# APT BRON Relation Extraction
Relation extraction from APT reports for the BRON knowledge graph


## The [BRON](https://github.com/ALFA-group/BRON) Graph

> Many public sources of cyber threat and vulnerability information exist to help defend cyber systems. [This paper](https://arxiv.org/pdf/2010.00533) links MITRE's ATT&CK MATRIX of Tactics and Techniques, NIST's Common Weakness Enumerations (CWE), Common Vulnerabilities and Exposures (CVE), and Common Attack Pattern Enumeration and Classification list (CAPEC), to gain further insight from alerts, threats and vulnerabilities. We preserve all entries and relations of the sources, while enabling bi-directional, relational path tracing within an aggregate data graph called BRON. In one example, we use BRON to enhance the information derived from a list of the top 10 most frequently exploited CVEs. We identify attack patterns, tactics, and techniques that exploit these CVEs and also uncover a disparity in how much linked information exists for each of these CVEs. This prompts us to further inventory BRON's collection of sources to provide a view of the extent and range of the coverage and blind spots of public data sources.

<br />
<p align="center">
  <img src="https://github.com/user-attachments/assets/b1d964a8-29d2-410b-9f62-1b761cdf2fc3" />
</p>


## Useful Links

### Data Sources

| Data Source | Explanation |
| ----------- | ----------- |
| [BRON Knowledge Graph](https://github.com/ALFA-group/BRON) | Threat data from MITRE ATT&CK, CAPEC, CWE , CVE, MITRE Engage, MITRE D3FEND, MITRE CAR and exploitdb data sources are linked together in a graph called BRON. |
| [APTnotes](https://github.com/aptnotes/data) | APTnotes is a repository of publicly-available papers and blogs (sorted by year) related to malicious campaigns/activity/software that have been associated with vendor-defined APT (Advanced Persistent Threat) groups and/or tool-sets. |
| [MITRE ATT&CK Matrix](https://attack.mitre.org/) | Tactics and techniques representing the MITRE ATT&CK® Matrix for Enterprise. |

### Types of Nodes

| Type | Explanation |
| ---- | ----------- |
| [Tactic](https://attack.mitre.org/tactics/enterprise/) | A high-level objective that an adversary tries to achieve during a cyberattack (e.g., [initial access](https://attack.mitre.org/tactics/TA0001/), [privilege escalation](https://attack.mitre.org/tactics/TA0004/), [data exfiltration](https://attack.mitre.org/tactics/TA0010/)) |
| [Group](https://attack.mitre.org/groups/) | A known threat actor or cybercriminal organization, tracked by MITRE based on its tactics, techniques, and procedures (TTPs) (e.g., [APT29](https://attack.mitre.org/groups/G0016/), [Lazarus Group](https://attack.mitre.org/groups/G0032/)) |
| [Software](https://attack.mitre.org/software/) | Malicious tools, malware, or utilities used by adversaries, including publicly available software and custom tools, categorized within the MITRE ATT&CK framework. (e.g., [Mimikatz](https://attack.mitre.org/software/S0002/), [Industroyer](https://attack.mitre.org/software/S0604/)) |
| [Technique](https://attack.mitre.org/techniques/enterprise/) | A specific method or approach used by attackers <ins>to accomplish a tactic</ins>, detailing how adversaries achieve their goals (e.g., [phishing](https://attack.mitre.org/techniques/T1566/), [credential dumping](https://attack.mitre.org/techniques/T1003/)) |
| [CAPEC](https://capec.mitre.org/) | A structured catalog of common attack patterns that adversaries use to <ins>exploit system weaknesses</ins>, focusing on how attacks are executed (e.g., [Server Side Include (SSI) Injection](https://capec.mitre.org/data/definitions/101.html), [Data Serialization External Entities Blowup](https://capec.mitre.org/data/definitions/221.html)) |
| [CWE](https://cwe.mitre.org/) | The Common Weakness Enumeration (CWE) is a MITRE list that categorizes software and hardware security weaknesses that could lead to vulnerabilities (e.g., [Incorrect Behavior Order: Authorization Before Parsing and Canonicalization](https://cwe.mitre.org/data/definitions/551.html), [Improper Handling of Parameters](https://cwe.mitre.org/data/definitions/233.html) |
| [CVE](https://nvd.nist.gov/) | The National Vulnerability Database (NVD) provides detailed information about known vulnerabilities in real products (CVE - Common Vulnerabilities and Exposures), including severity ratings and mitigation steps (e.g., [CVE-2022-25454](https://nvd.nist.gov/vuln/detail/cve-2022-25454), [CVE-2025-24201](https://nvd.nist.gov/vuln/detail/CVE-2025-24201)) |
| [CPE](https://nvd.nist.gov/) | The Common Platform Enumeration (CPE) is a standardized naming scheme used by NVD to identify and describe hardware, software, and firmware affected by vulnerabilities (e.g., [cpe:2.3:a:apple:safari:17.6:*:*:*:*:*:*:*]) |


## Task

**The goal is to extract new edges from the reports to enrich the BRON knowledge graph.**

### Possible Implementation Techniques
[NER (Named Entity Recognition](https://www.ibm.com/think/topics/named-entity-recognition) is a natural language processing (NLP) technique that identifies and classifies key elements (in our case attack patterns, cves, weaknesses, etc...) within unstructured text.

### Output Format
The output format should be a JSON file that contains a list of edges of the following schema:
```json
[
  {
    "from": "node1_id",
    "to": "node2_id",
    "source": ["source_doc1", "source_doc2", "..."],
    "justification": "optional - why is node1 connected to node2"
  },
  "..."
]
```

## Getting Started

### Get your own BRON
To get access to the BRON graph, and have it locally so you can query it when needed, you should load the BRON graph to your machine. Follow the steps below:
1. [Download Neo4j](https://neo4j.com/download/) - this is the client you will use in order to load BRON, and explore it manually or via python code.
2. [Download BRON](https://ibm-my.sharepoint.com/:u:/r/personal/daniel_ohayon_ibm_com/Documents/Starships/neo4j.dump?csf=1&web=1&e=FPbrPU) - you will load the BRON knowledge graph from this file that contains all the information about it in Neo4j language.
3. Add BRON dump to the client - in the Neo4j client: Add -> File -> (choose bron dump)
4. Create database from the dump - in the Neo4j cleint: Click on the `...` icon next to the BRON dump file -> Create new DBMS from dump

### Neo4j Guides
* [Neo4j Python Package](https://neo4j.com/docs/python-manual/current/) - this is the python package you will use in order to interface with the BRON graph.
* [Cypher Docummentation (Neo4j Query Language)](https://neo4j.com/docs/cypher-manual/current/introduction/) - this is the language you will use to query the graph (e.g., getting nodes, relationships, etc...)
