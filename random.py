""""
title: Mixture of Agents Pipe
author: MaxKerkula (adapted as pipe by srossitto79)
version: 0.4
required_open_webui_version: 0.3.9
"""

from pydantic import BaseModel, Field
from typing import (
    Optional,
    List,
    Callable,
    Awaitable,
    Union,
    Generator,
    Iterator,
    AsyncGenerator,
)
import aiohttp
import random
import asyncio
import time
from utils.misc import get_last_user_message
from utils.misc import pop_system_message


class Pipe:
    class Valves(BaseModel):
        models: List[str] = Field(
            default=[], description="List of models to use in the MoA architecture."
        )
        aggregator_model: str = Field(
            default="", description="Model to use for aggregation tasks."
        )
        openai_api_base: str = Field(
            default="http://ollama:11434/v1",
            description="Base URL for Ollama API.",
        )
        num_layers: int = Field(default=1, description="Number of MoA layers.")
        num_agents_per_layer: int = Field(
            default=3, description="Number of agents to use in each layer."
        )
        emit_interval: float = Field(
            default=1.0, description="Interval in seconds between status emissions"
        )
        enable_status_indicator: bool = Field(
            default=True, description="Enable or disable status indicator emissions"
        )

    def __init__(self):
        self.valves = self.Valves()
        self.last_emit_time = 0

    async def pipe(self, body: dict) -> Union[str, Generator, Iterator]:
        system_message, messages = pop_system_message(body.get("messages", []))

        async def print_event(message) -> AsyncGenerator[str, None]:
            print(message)

        __event_emitter__ = print_event

        await self.emit_status(
            __event_emitter__, "info", "Starting Mixture of Agents process", False
        )

        try:
            await self.validate_models(__event_emitter__)
        except ValueError as e:
            await self.emit_status(__event_emitter__, "error", str(e), True)
            raise {"error": str(e)}

        if not messages:
            error_msg = "No messages found in the request body"
            await self.emit_status(__event_emitter__, "error", error_msg, True)
            raise {"error": error_msg}

        last_message = messages[-1]["content"]
        moa_response = await self.moa_process(last_message, __event_emitter__)

        if moa_response.startswith("Error:"):
            await self.emit_status(__event_emitter__, "error", moa_response, True)
            raise {"error": moa_response}

        yield moa_response

        await self.emit_status(
            __event_emitter__, "info", "Mixture of Agents process completed", True
        )


    async def validate_models(
        self, __event_emitter__: Callable[[dict], Awaitable[None]] = None
    ):
        await self.emit_status(__event_emitter__, "info", "Validating models", False)
        valid_models = []
        for model in self.valves.models:
            response = await self.query_ollama(model, "Test prompt", __event_emitter__)
            if not response.startswith("Error:"):
                valid_models.append(model)

        if not valid_models:
            error_msg = (
                "No valid models available. Please check your model configurations."
            )
            await self.emit_status(__event_emitter__, "error", error_msg, True)
            raise ValueError(error_msg)

        self.valves.models = valid_models
        await self.emit_status(
            __event_emitter__, "info", f"Validated {len(valid_models)} models", False
        )

    async def moa_process(
        self, prompt: str, __event_emitter__: Callable[[dict], Awaitable[None]] = None
    ) -> str:
        if (
            not self.valves.models
            or not self.valves.aggregator_model
            or not self.valves.openai_api_base
        ):
            error_msg = "Configuration error: Models, aggregator model, or API base URL not set."
            await self.emit_status(__event_emitter__, "error", error_msg, True)
            return f"Error: {error_msg}"

        if len(self.valves.models) < self.valves.num_agents_per_layer:
            error_msg = f"Not enough models available. Required: {self.valves.num_agents_per_layer}, Available: {len(self.valves.models)}"
            await self.emit_status(__event_emitter__, "error", error_msg, True)
            return f"Error: {error_msg}"

        layer_outputs = []
        for layer in range(self.valves.num_layers):
            await self.emit_status(
                __event_emitter__,
                "info",
                f"Processing layer {layer + 1}/{self.valves.num_layers}",
                False,
            )

            layer_agents = random.sample(
                self.valves.models,
                self.valves.num_agents_per_layer,
            )

            tasks = [
                self.process_agent(
                    prompt, agent, layer, i, layer_outputs, __event_emitter__
                )
                for i, agent in enumerate(layer_agents)
            ]
            current_layer_outputs = await asyncio.gather(*tasks)

            valid_outputs = [
                output
                for output in current_layer_outputs
                if not output.startswith("Error:")
            ]
            if not valid_outputs:
                error_msg = (
                    f"No valid responses received from any agent in layer {layer + 1}"
                )
                await self.emit_status(__event_emitter__, "error", error_msg, True)
                return f"Error: {error_msg}"

            layer_outputs.append(valid_outputs)
            await self.emit_status(
                __event_emitter__,
                "info",
                f"Completed layer {layer + 1}/{self.valves.num_layers}",
                False,
            )

        await self.emit_status(
            __event_emitter__, "info", "Creating final aggregator prompt", False
        )
        final_prompt = self.create_final_aggregator_prompt(prompt, layer_outputs)

        await self.emit_status(
            __event_emitter__, "info", "Generating final response", False
        )
        final_response = await self.query_ollama(
            self.valves.aggregator_model, final_prompt, __event_emitter__
        )

        if final_response.startswith("Error:"):
            await self.emit_status(
                __event_emitter__, "error", "Failed to generate final response", True
            )
            return f"Error: Failed to generate final response. Last error: {final_response}"

        return final_response

    async def process_agent(
        self, prompt, agent, layer, agent_index, layer_outputs, __event_emitter__
    ):
        await self.emit_status(
            __event_emitter__,
            "info",
            f"Querying agent {agent_index + 1} in layer {layer + 1}",
            False,
        )

        if layer == 0:
            response = await self.query_ollama(agent, prompt, __event_emitter__)
        else:
            await self.emit_status(
                __event_emitter__,
                "info",
                f"Creating aggregator prompt for layer {layer + 1}",
                False,
            )
            aggregator_prompt = self.create_aggregator_prompt(prompt, layer_outputs[-1])
            response = await self.query_ollama(
                self.valves.aggregator_model, aggregator_prompt, __event_emitter__
            )

        await self.emit_status(
            __event_emitter__,
            "info",
            f"Received response from agent {agent_index + 1} in layer {layer + 1}",
            False,
        )
        return response

    def create_aggregator_prompt(
        self, original_prompt: str, previous_responses: List[str]
    ) -> str:
        aggregator_prompt = (
            f"Original prompt: {original_prompt}\n\nPrevious responses:\n"
        )
        for i, response in enumerate(previous_responses, 1):
            aggregator_prompt += f"{i}. {response}\n\n"
        aggregator_prompt += "Based on the above responses and the original prompt, provide an improved and comprehensive answer:"
        return aggregator_prompt

    def create_final_aggregator_prompt(
        self, original_prompt: str, all_layer_outputs: List[List[str]]
    ) -> str:
        final_prompt = (
            f"Original prompt: {original_prompt}\n\nResponses from all layers:\n"
        )
        for layer, responses in enumerate(all_layer_outputs, 1):
            final_prompt += f"Layer {layer}:\n"
            for i, response in enumerate(responses, 1):
                final_prompt += f" {i}. {response}\n\n"
        final_prompt += (
            "Considering all the responses from different layers and the original prompt, provide a final, comprehensive answer that strictly adheres to the original request:\n"
            "1. Incorporate relevant information from all previous responses seamlessly.\n"
            "2. Avoid referencing or acknowledging previous responses explicitly unless directed by the prompt.\n"
            "3. Provide a complete and detailed reply addressing the original prompt."
        )
        return final_prompt

    async def query_ollama(
        self,
        model: str,
        prompt: str,
        __event_emitter__: Callable[[dict], Awaitable[None]] = None,
    ) -> str:
        url = f"{self.valves.openai_api_base}/chat/completions"
        headers = {"Content-Type": "application/json"}
        data = {"model": model, "messages": [{"role": "user", "content": prompt}]}

        try:
            await self.emit_status(
                __event_emitter__,
                "info",
                f"Sending API request to model: {model}",
                False,
            )

            async with aiohttp.ClientSession() as session:
                async with session.post(url, headers=headers, json=data) as response:
                    if response.status == 404:
                        error_message = f"Model '{model}' not found. Please check if the model is available and correctly specified."
                        await self.emit_status(
                            __event_emitter__, "error", error_message, True
                        )
                        return f"Error: {error_message}"

                    response.raise_for_status()
                    result = await response.json()

            await self.emit_status(
                __event_emitter__,
                "info",
                f"Received API response from model: {model}",
                False,
            )

            return result["choices"][0]["message"]["content"]
        except aiohttp.ClientResponseError as e:
            error_message = f"HTTP error querying Ollama API for model {model}: {e.status}, {e.message}"
            await self.emit_status(__event_emitter__, "error", error_message, True)
            print(error_message)
            return f"Error: Unable to query model {model} due to HTTP error {e.status}"
        except aiohttp.ClientError as e:
            error_message = (
                f"Network error querying Ollama API for model {model}: {str(e)}"
            )
            await self.emit_status(__event_emitter__, "error", error_message, True)
            print(error_message)
            return f"Error: Unable to query model {model} due to network error"
        except Exception as e:
            error_message = (
                f"Unexpected error querying Ollama API for model {model}: {str(e)}"
            )
            await self.emit_status(__event_emitter__, "error", error_message, True)
            print(error_message)
            return f"Error: Unable to query model {model} due to unexpected error"

    async def emit_status(
        self,
        __event_emitter__: Callable[[dict], Awaitable[None]],
        level: str,
        message: str,
        done: bool,
    ):
        current_time = time.time()
        if (
            __event_emitter__
            and self.valves.enable_status_indicator
            and (
                current_time - self.last_emit_time >= self.valves.emit_interval or done
            )
        ):
            await __event_emitter__(
                {
                    "type": "status",
                    "data": {
                        "status": "complete" if done else "in_progress",
                        "level": level,
                        "description": message,
                        "done": done,
                    },
                }
            )
            self.last_emit_time = current_time

    async def on_start(self):
        print("Mixture of Agents Action started")

    async def on_stop(self):
        print("Mixture of Agents Action stopped")


# The implementation approach and improvements are based on best practices and examples from GitHub repositories such as:
# - [Together MoA Implementation](https://github.com/togethercomputer/MoA)
# - [MX-Goliath/MoA-Ollama](https://github.com/MX-Goliath/MoA-Ollama)
# - [AI-MickyJ/Mixture-of-Agents](https://github.com/AI-MickyJ/Mixture-of-Agents)
