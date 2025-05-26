def build_prompt(article_text: str, entity_a: str, entity_b: str) -> str:
    """
    Builds a natural language prompt asking Watsonx whether there is a relationship
    (edge) between two entities in the context of a given article.

    Parameters:
        article_text (str): The full text of the document.
        entity_a (str): The name or label of the first entity.
        entity_b (str): The name or label of the second entity.

    Returns:
        str: A formatted prompt string to send to the LLM.
    """
    prompt = f"""
You are a cybersecurity analyst.

Given the following document:

\"\"\"{article_text}\"\"\"

Evaluate whether there is a meaningful relationship (an edge) between the two entities mentioned below in the context of the document.

Entity A: {entity_a}
Entity B: {entity_b}

Please answer with **Yes** or **No**, and explain your reasoning in one or two sentences.

Only include explanations that are supported by the document.
"""
    return prompt.strip()
