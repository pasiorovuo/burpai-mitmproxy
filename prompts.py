import abc
import enum
import json
import typing

DEFAULT_MODEL = "gpt-4o"


class Role(str, enum.Enum):
    SYSTEM = "system"
    USER = "user"


class Message(typing.TypedDict):
    role: Role
    content: str


class Prompt(abc.ABC):
    _max_tokens: int = 500
    _model: str = DEFAULT_MODEL
    _temperature: float = 1.0

    @classmethod
    def set_model(cls, model: str) -> None:
        cls._model = model

    @classmethod
    def model(cls) -> str:
        return cls._model or DEFAULT_MODEL

    def __init__(self, messages: typing.List[Message]) -> None:
        super().__init__()
        self.messages = messages

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
                "messages": self.messages,
                "max_completion_tokens": self.max_tokens,
                "temperature": self.temperature,
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
    def max_tokens(self) -> int:
        return self._max_tokens

    @property
    def temperature(self) -> float:
        return self._temperature


class ExplainThisPrompt(Prompt):
    def __init__(self, payload: str | None) -> None:
        super().__init__(
            messages=[
                {"role": Role.SYSTEM, "content": self.system_prompt},
                {"role": Role.USER, "content": payload or ""},
            ]
        )

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

    _max_tokens = 128000

    def __init__(self, payload: str | None) -> None:
        j = json.loads(payload or "{}")

        messages: typing.List[Message] = []
        for m in j.get("messages", []):
            if m.get("type", "").lower() == "system":
                messages.append({"role": Role.SYSTEM, "content": m.get("text", "")})
            elif m.get("type", "").lower() == "user":
                messages.append({"role": Role.USER, "content": m.get("text", "")})

        super().__init__(messages=messages)

        # Parse config
        if "config" in j:
            config = j["config"]

            if "temperature" in config:
                try:
                    temperature = float(config["temperature"])
                except ValueError:
                    temperature = 1.0

                if 0.0 <= temperature <= 2.0:
                    self._temperature = temperature

    @property
    def temperature(self) -> float:
        return self._temperature
