def format_entity(entity: dict, label: str) -> str:
    name = entity.get("name", "Unknown")
    ent_type = entity.get("type", "Unknown")
    description = entity.get("description", "No description provided")

    lines = [f"{label}:", f"- Name: {name}", f"- Type: {ent_type}"]

    if ent_type == "group":
        lines.append(f"- Aliases: {', '.join(entity.get('all_aliases', [])) or 'None'}")
        lines.append(f"- Description: {description}")

    elif ent_type == "cwe":
        consequences = entity.get("common_consequences", [])
        lines.append(f"- CWE ID: {entity.get('original_id', 'N/A')}")
        lines.append(f"- Description: {description}")
        lines.append(f"- Common Consequences: {', '.join(consequences) or 'None'}")
        lines.append(f"- Likelihood of Exploit: {entity.get('likelihood_of_exploit', 'Unknown')}")

    elif ent_type == "software":
        lines.append(f"- Software Type: {entity.get('software_type', 'Unknown')}")
        lines.append(f"- Description: {description}")

    elif ent_type == "technique":
        lines.append(f"- Technique ID: {entity.get('original_id', 'N/A')}")
        lines.append(f"- Description: {description}")

    elif ent_type == "tactic":
        lines.append(f"- Tactic ID: {entity.get('original_id', 'N/A')}")
        lines.append(f"- Description: {description}")

    elif ent_type == "capec":
        consequences = entity.get("consequences", [])
        lines.append(f"- CAPEC ID: {entity.get('original_id', 'N/A')}")
        lines.append(f"- Description: {description}")
        lines.append(f"- Common Consequences: {', '.join(consequences) or 'None'}")
        lines.append(f"- Likelihood of Exploit: {entity.get('likelihood_of_exploit', 'Unknown')}")
        lines.append(f"- Skills Required: {entity.get('skills_required', 'Unknown')}")
        lines.append(f"- Typical Severity: {entity.get('typical_severity', 'Unknown')}")

    else:
        lines.append(f"- Description: {description}")

    return "\n".join(lines)

# def build_prompt(article_text: str, entity_a: dict, entity_b: dict) -> str:
def build_prompt() -> str:

    """
    Returns a PromptTemplate for generating cybersecurity edge detection prompts.
    Uses placeholders: {article_text}, {entity_a}, {entity_b}
    """

    return """
You are a cybersecurity analyst.
=====================
Document:
{article_text}
=====================
Entity A:
{entity_a}
=====================
Entity B:
{entity_b}
=====================
Task:
Based on the article and the context of the two entities above, 
determine whether there is a meaningful connection (an edge) between them in a cybersecurity context.

Instructions:
- Think carefully about whether each entity is clearly mentioned, referenced, or implied in the article.
- If **either entity is not found or strongly implied**, consider that the confidence in that side is low.
- Base your connection judgment only on information found or supported by the article.
- Respond with:
    <think>Provide your thinking process here</think>
    <answer>Yes or No</answer>
    <confidence>Low, Medium, or High</confidence>

""".strip()


#{ "think": "...", "link": True/False }