import abc
import json

DEFAULT_MODEL = "gpt-4o"


class Prompt(abc.ABC):
    _max_tokens: int = 500
    _model: str = DEFAULT_MODEL

    @classmethod
    def set_model(cls, model: str) -> None:
        cls._model = model

    @classmethod
    def model(cls) -> str:
        return cls._model or DEFAULT_MODEL

    def __init__(self, payload: str | None) -> None:
        super().__init__()
        self.payload = payload

    def __str__(self) -> str:
        return json.dumps(self.text())

    def text(self) -> str:
        """
        Construct the JSON payload to send to the AI service. Contains the
        fields to migrate to responses api in the future.
        """
        return json.dumps(
            {
                "model": Prompt.model(),
                "messages": [
                    {"role": "system", "content": self.system_prompt},
                    {"role": "user", "content": self.payload},
                ],
                "max_completion_tokens": self.max_tokens,
                "response_format": {
                    # "json_schema": {
                    #     "name": "burp_ai",
                    #     "schema": {
                    #         "type": "object",
                    #         "properties": {
                    #             "content": {"type": "string"},
                    #         },
                    #         "required": ["content"],
                    #     },
                    #     "strict": True,
                    # },
                    "type": "text",
                },
                # "include": [],
                # "input": self.payload,
                # "instructions": self.system_prompt,
                # "input": [
                #     {"role": "system", "content": self.system_prompt},
                #     {"role": "user", "content": self.payload},
                # ],
                # "max_output_tokens": self.max_tokens,
                # "max_tool_calls": 0,
                # "temperature": 1,
                # "text": {
                #     "format": {
                #         "name": "burp_ai",
                #         "type": "json_schema",
                #         "schema": {
                #             "type": "object",
                #             "properties": {
                #                 "content": {"type": "string"},
                #             },
                #             "required": ["content"],
                #         },
                #         "strict": True,
                #     }
                # },
            }
        )

    @property
    @abc.abstractmethod
    def system_prompt(self) -> str: ...

    @property
    def max_tokens(self) -> int:
        return self._max_tokens


class ExplainThisPrompt(Prompt):
    @property
    def system_prompt(self) -> str:
        return (
            "You are an expert security researcher analyzing a HTTP request or a response. "
            "Provide a short explanation of the given text, briefly summarizing any potential "
            "security implications from an attacker perspective. "
            "Do not include mitigation recommendations or other descriptions. "
            "Minimize the use of newlines."
        )


class MontoyaPrompt(Prompt):
    """
    Burp Extensions use API for AI interactions.
    """

    _system_prompt: str

    def __init__(self, payload: str | None) -> None:
        j = json.loads(payload or "{}")

        system_prompt = user_prompt = ""
        for message in j.get("messages", []):
            if message.get("type", "").lower() == "system":
                system_prompt = message.get("text", "")
            elif message.get("type", "").lower() == "user":
                user_prompt = message.get("text", "")

        super().__init__(user_prompt)
        self._system_prompt = system_prompt

    @property
    def system_prompt(self) -> str:
        return self._system_prompt
