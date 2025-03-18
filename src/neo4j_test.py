import os

from neo4j import GraphDatabase
from dotenv import load_dotenv

load_dotenv()

URI = os.environ["NEO4J_URI"]
USERNAME = os.environ["NEO4J_USERNAME"]
PASSWORD = os.environ["NEO4J_PASSWORD"]

NODE_COUNT_QUERY = """
CALL db.labels() YIELD label
CALL apoc.cypher.run('MATCH (:`' + label + '`) RETURN count(*) as count', {}) YIELD value
RETURN label, value.count AS nodeCount
"""

EDGE_COUNT_QUERY = """
CALL db.relationshipTypes() YIELD relationshipType AS type
CALL apoc.cypher.run('MATCH ()-[:`' + type + '`]->() RETURN count(*) as count', {}) YIELD value
RETURN type, value.count AS relationshipCount
"""

EXPECTED_NODE_COUNT = {
    "software": 648,
    "capec": 559,
    "capec_mitigation": 1172,
    "cwe_detection": 712,
    "cve": 487593,
    "cwe": 938,
    "group": 141,
    "technique_detection": 581,
    "d3fend_mitigation": 382,
    "cwe_mitigation": 1654,
    "technique_mitigation": 43,
    "capec_detection": 96,
    "tactic": 14,
    "technique": 625,
    "cpe": 549957,
}


EXPECTED_EDGE_COUNT = {
    "IS_PARENT_OF_ATTACK_PATTERN": 533,
    "IS_DETECTED_BY": 1389,
    "EXPLOITS_WEAKNESS": 2171,
    "IS_ACHIEVED_BY": 812,
    "IS_MITIGATED_BY": 4000,
    "IS_MITIGATED_BY_D3FEND_MITIGATION": 180,
    "IS_USED_BY_ATTACK_PATTERN": 270,
    "IS_USING_SOFTWARE": 870,
    "USED_TECHNIQUE": 3188,
    "IS_USING_TECHNIQUE": 8568,
    "IS_PARENT_OF_SUB_TECHNIQUE": 424,
    "BEING_EXPLOITED_IN": 740337,
    "IS_COMPROMISING_PLATFORM": 10538258,
    "IS_PARENT_OF_WEAKNESS": 1158
}

with GraphDatabase.driver(URI, auth=(USERNAME, PASSWORD)) as driver:
    driver.verify_connectivity()

    records, _, _ = driver.execute_query(NODE_COUNT_QUERY)
    node_count = {}
    for (label, nodeCount) in records:
        node_count[label] = nodeCount
    
    assert node_count == EXPECTED_NODE_COUNT, "Node count does not match"
    
    records, _, _ = driver.execute_query(EDGE_COUNT_QUERY)
    edge_count = {}
    for (type, relationshipCount) in records:
        edge_count[type] = relationshipCount

    assert edge_count == EXPECTED_EDGE_COUNT, "Edge count does not match"

print("All tests passed")