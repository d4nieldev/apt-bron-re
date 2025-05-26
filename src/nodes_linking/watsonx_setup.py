import os
import time
from dotenv import load_dotenv
from ibm_watsonx_ai import APIClient, Credentials
from ibm_watsonx_ai.foundation_models.utils.enums import DecodingMethods
from ibm_watsonx_ai.metanames import GenTextParamsMetaNames
from langchain_ibm import ChatWatsonx
from langchain.prompts import PromptTemplate
from langchain.output_parsers import BooleanOutputParser

# === Load environment variables ===
load_dotenv()
# print("API KEY:", os.getenv("WATSONX_APIKEY"))  # debug


# === Set up IBM WatsonX credentials ===
credentials = Credentials(
    url=os.getenv("WATSONX_URL"),
    api_key=os.getenv("WATSONX_APIKEY")
)

# === Define LLM loader ===
def get_llm(
    model_id: str,
    decoding_method: DecodingMethods = DecodingMethods.SAMPLE,
    min_new_tokens: int = 1,
    max_new_tokens: int = 1024,
    temperature: float = 0.7,
    top_k: int = 50,
    top_p: float = 1,
    repetition_penalty: float = 1.0,
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

if __name__ == "__main__":
    client = APIClient(credentials)
    models = client.foundation_models.get_model_specs()
