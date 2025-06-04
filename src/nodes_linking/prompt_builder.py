# def build_prompt(article_text: str, entity_a: dict, entity_b: dict) -> str:
#     """
#     Builds an enriched prompt for the LLM, incorporating entity descriptions and roles.
#
#     Parameters:
#         article_text (str): The full document text.
#         entity_a (dict): Metadata for entity A (for example: 'name', 'type', 'description').
#         entity_b (dict): Metadata for entity B.
#
#     Returns:
#         str: A formatted prompt string for LLM.
#     """
#     prompt = f"""
# You are a cybersecurity analyst.
# Analyze the following article for evidence of a meaningful connection (an edge) between two cybersecurity-related entities.
# Only confirm a relationship if the article provides direct or indirect evidence connecting their roles, behavior, or context.
#
# =====================
# Document:
# \"\"\"{article_text}\"\"\"
#
# =====================
#  Entity A:
# - Name: {entity_a.get("name")}
# - Type: {entity_a.get("type")}
# - Description: {entity_a.get("description", "No description provided")}
#
#  Entity B:
# - Name: {entity_b.get("name")}
# - Type: {entity_b.get("type")}
# - Description: {entity_b.get("description", "No description provided")}
#
# =====================
#
# Task:
# Based on the article, determine whether **Entity A** and **Entity B** are meaningfully related (i.e., whether there's a relevant edge between them in the cybersecurity context).
#
# Answer in the following format:
#
# **Yes** or **No**
#
# Please answer with **Yes** or **No**, and explain your reasoning in one or two sentences.
#
# Then, provide a short explanation based strictly on the article.
#
# Avoid speculation — only use information grounded in the provided document.
#
# """
#     return prompt.strip()


def build_prompt(article_text: str, entity_a: dict, entity_b: dict) -> str:
    """
    Builds a rich prompt with type-specific entity formatting.
    """

    def format_entity(entity: dict, label: str) -> str:
        name = entity.get("name", "Unknown")
        ent_type = entity.get("type", "Unknown")
        description = entity.get("description", "No description provided")

        lines = [f"{label}:", f"- Name: {name}", f"- Type: {ent_type}"]

        if ent_type == "group":
            lines.append(f"- all_aliases: {', '.join(entity.get('all_aliases', [])) or 'None'}")
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

        else:
            lines.append(f"- Description: {description}")

        return "\n".join(lines)

    entity_a_str = format_entity(entity_a, "🔹 Entity A")
    entity_b_str = format_entity(entity_b, "🔹 Entity B")

    prompt = f"""
You are a cybersecurity analyst.
Analyze the following article for evidence of a meaningful connection (an edge) between two cybersecurity-related entities. 
Only confirm a relationship if the article provides direct or indirect evidence connecting their roles, behavior, or context.

=====================
📰 Document:
\"\"\"{article_text}\"\"\"

=====================
{entity_a_str}

{entity_b_str}

=====================
📌 Task:
Based on the article, determine whether **Entity A** and **Entity B** are meaningfully related (i.e., whether there's a relevant edge between them in the cybersecurity context).

Answer in the following format:

**Yes** or **No**

Then explain your reasoning in one or two sentences, using only information from the article. Avoid speculation.
"""
    return prompt.strip()
