import os
import asyncio
import logging
from threading import Lock
from typing import Generic, TypeVar, Optional, Union
from dataclasses import dataclass, asdict

from dotenv import load_dotenv
from tqdm import tqdm

from ibm_watsonx_ai import APIClient, Credentials
from ibm_watsonx_ai.foundation_models.utils.enums import DecodingMethods
from ibm_watsonx_ai.metanames import GenTextParamsMetaNames

from langchain_ibm import ChatWatsonx
from langchain_core.runnables import RunnableLambda
from langchain_core.output_parsers import (
    BaseOutputParser,
    BaseGenerationOutputParser,
    StrOutputParser,
)
from langchain_core.prompts import PromptTemplate

import nest_asyncio
nest_asyncio.apply()

# === Load environment variables ===
load_dotenv()
print("API KEY:", os.getenv("WATSONX_APIKEY"))  # debug


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

# === Typed result structure for generated prompts ===
ResultType = TypeVar("ResultType")

@dataclass
class GenerationResult(Generic[ResultType]):
    input: dict[str, str]
    prompt: str
    result: ResultType

    def dict(self):
        return asdict(self)

# === Batch generate prompts with retries ===
def generate_many(
        prompt: str,
        inputs: list[dict[str, str]],
        llm: ChatWatsonx,
        num_retries: int = 0,
        output_parser: Union[BaseOutputParser[ResultType], BaseGenerationOutputParser[ResultType]] = StrOutputParser(),
        description: str = "Generating",
) -> list[GenerationResult[Optional[ResultType]]]:
    """
    Generates prompts for a list of inputs using the LLM model

    Args:
        prompt (str): The prompt to be used.
        inputs (list[dict[str, str]]): The inputs to be used.
        llm (BaseLanguageModel): The LLM model to be used.
        num_retries (int, optional): The number of retries to be used in case the output parser fails. -1 means infinite retries (use with caution!). Defaults to 0 (try every input only once).
        output_parser (BaseOutputParser[ResultType], optional): The output parser to be used. Defaults to StrOutputParser().
        description (str, optional): The description to be used in the progress bar. Defaults to "Generating".

    Returns:
        list[GenerationResult[Optional[ResultType]]]: The results of the generation process.
    """
    progress_bar = tqdm(total=len(inputs), desc=description)
    lock = Lock()

    def track_progress(result):
        if not isinstance(result, Exception):
            with lock:
                progress_bar.update(1)
        return result

    async def run_parallel(tasks):
        return await asyncio.gather(*tasks,return_exceptions=True)

    template = PromptTemplate.from_template(prompt)
    show_progress = RunnableLambda(track_progress)

    llm_chain = (template | llm | output_parser | show_progress)

    # generate with retry
    results = [None] * len(inputs)
    tries = 0
    while None in results and (num_retries == -1 or tries <= num_retries):
        # get remaining inputs
        remaining_inputs = [(i, inp) for i, (inp, res) in enumerate(zip(inputs, results)) if res is None]

        # generate
        outputs = asyncio.run(run_parallel(tasks=[llm_chain.ainvoke(inp) for _, inp in remaining_inputs]))

        # update results
        for (i, _), output in zip(remaining_inputs, outputs):
            if not isinstance(output, Exception):
                results[i] = output  # type: ignore
            else:
                logging.info(f"Exception while generating response: {output}. Retrying...")

        # increment tries counter
        tries += 1

    failed_count = len([res for res in results if res is None])
    if failed_count > 0:
        logging.warning(f"{failed_count} prompts failed. Replaced with None.")

    return [GenerationResult(input=inp, prompt=prompt.format(**inp), result=res)
        for inp, res in zip(inputs, results)]

if __name__ == "__main__":
    client = APIClient(credentials)
    models = client.foundation_models.get_model_specs()
