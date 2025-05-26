import os
import json
from dotenv import load_dotenv
from ibm_watsonx_ai import APIClient, Credentials
from ibm_watsonx_ai.foundation_models.utils.enums import DecodingMethods
from ibm_watsonx_ai.metanames import GenTextParamsMetaNames
from langchain_ibm import ChatWatsonx
import time
from langchain.output_parsers import BooleanOutputParser
from langchain.prompts import PromptTemplate

# Load environment variables from .env
load_dotenv()
print("API KEY:", os.getenv("WATSONX_APIKEY"))  # ← הדפסת דיבאג


# Set up credentials for WatsonX
credentials = Credentials(
    url=os.getenv("WATSONX_URL"),
    api_key=os.getenv("WATSONX_APIKEY")
)

# Define a function to return an LLM instance
def get_llm(
    model_id: str,
    decoding_method: DecodingMethods = DecodingMethods.SAMPLE,
    min_new_tokens: int = 1,
    max_new_tokens: int = 1024,
    temperature: float = 0.7,
    top_k: int = 50,
    top_p: float = 1,
    repetition_penalty: float = 1.05,
    stop_sequences: list[str] = None,
    **llm_kwargs
) -> ChatWatsonx:
    return ChatWatsonx(
        model_id=model_id,
        url=os.environ['WATSONX_URL'],
        apikey=os.environ['WATSONX_APIKEY'],
        project_id=os.environ['WATSONX_PROJECT_ID'],
        params={
            GenTextParamsMetaNames.DECODING_METHOD: decoding_method.value,
            GenTextParamsMetaNames.MIN_NEW_TOKENS: min_new_tokens,
            GenTextParamsMetaNames.MAX_NEW_TOKENS: max_new_tokens,
            GenTextParamsMetaNames.TEMPERATURE: temperature,
            GenTextParamsMetaNames.TOP_K: top_k,
            GenTextParamsMetaNames.TOP_P: top_p,
            GenTextParamsMetaNames.REPETITION_PENALTY: repetition_penalty,
            GenTextParamsMetaNames.STOP_SEQUENCES: stop_sequences or []
        },
        **llm_kwargs
    )


prompt = "Is {capital} the capital of {country}?\nAnswer ONLY with 'yes' or 'no'."
template = PromptTemplate.from_template(prompt)
llm = get_llm("mistralai/mistral-large", decoding_method=DecodingMethods.GREEDY)
parser = BooleanOutputParser()

chain = template | llm | parser

inputs = [
    {"country": "France", "capital": "Paris"},      # True
    {"country": "Israel", "capital": "Jerusalem"},  # True
    {"country": "Turkey", "capital": "Istanbul"},   # False
]

results = []

t0 = time.time()
for inp in inputs:
    results.append(chain.invoke(inp))

print(f"Time taken: {time.time() - t0:.2f} seconds")
print(results)  # [True, True, False]

# Sample usage
if __name__ == "__main__":
    # List available models from WatsonX
    client = APIClient(credentials)
    models = client.foundation_models.get_model_specs()
    llm = get_llm("meta-llama/llama-3-3-70b-instruct")


    # Call the model
    # llm = get_llm("meta-llama/llama-3-3-70b-instruct")
    result = llm.invoke("Hello, how are you?")
    print(result.content)
