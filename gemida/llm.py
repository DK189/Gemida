import os
import json
import re
# import google.generativeai as genai
import idaapi

from google import genai
from pydantic import BaseModel

MODEL_NAME = "gemini-2.5-flash"

PROMPT_TEMPLATE = """You are analyzing C pseudocode from reverse engineering.
Task: For each function, provide analysis:
- "new_name": a meaningful new function name (valid C identifier).
  * Only rename functions whose original name matches sub_* or nullsub_*.
  * For other functions, keep the same name as new_name.
- "comment": a one-line explanation of the function's purpose.
  * Only add a comment if the function is renamed, or if the original function name is unclear and has no existing comment.
  * If the function already has a meaningful name or has an existing comment, do not add a new comment.

Rules:
- Output must be valid minified JSON object only, without explanations or markdown or escape.
- Output format:
{{
  "old_function_name": {{
    "new_name": "new_function_name",
    "comment": "[Gemida] a one-line explanation of the function's purpose."  // optional, may be omitted
  }},
  ...
}}
- Each key is the original function name (e.g., sub_A26920).
- All comments must start with "[Gemida] ".
- Destructor functions must not use '~'. Instead, append "__DESTRUCTOR__".
- The full JSON output must not exceed 50,000 characters. If necessary, shorten or omit comments to stay within this limit.

Functions pseudocode:
{functions}
"""

class ModelResponseEntry(BaseModel):
    new_name: str
    comment: str | None = None
    
#######################################################


def analyze_functions(group):
    if os.getenv("GEMIDA_API_KEY") is None:
        idaapi.msg("[Gemida] Missing GEMIDA_API_KEY environment variable!\n")
        return {}

    client = genai.Client(api_key=os.getenv("GEMIDA_API_KEY"))

    # genai.configure(api_key=API_KEY)
    # model = genai.GenerativeModel(MODEL_NAME)

    functions_text = "\n\n".join(
        f"// Function: {name}\n{code}" for name, code in group.items()
    )
    prompt = PROMPT_TEMPLATE.format(functions=functions_text)

    idaapi.msg(f"[Gemida] Sending request to Gemini model '{MODEL_NAME}'...\n")
    idaapi.msg(f"[Gemida] Prompt:\n{prompt}\n")

    try:
        resp = client.models.generate_content(
            model=MODEL_NAME,
                contents=prompt,
                config={
                    "response_mime_type": "application/json",
                    # "response_schema": dict[str, AllowedType],
                },
        )
        # resp = model.generate_content(
        #     prompt,
        #     generation_config=genai.GenerationConfig(
        #         temperature=0.2,
        #         response_mime_type="application/json"
        #     )
        # )
        text = resp.text or ""
        idaapi.msg(f"[Gemida] Gemini response received.\n")
        idaapi.msg(f"[Gemida] Full response:\n{text}\n")
        # Extract JSON block if extra text is present
        # match = re.search(r"\{.*\}", text, re.S)
        # if not match:
        #     idaapi.msg(f"[Gemida] Gemini returned non-JSON response:\n{text}\n")
        #     return {}
        # json_text = match.group(0)
        # return json.loads(json_text)
        return json.loads(text)
        # return resp.parsed.__dict__
        # return json.loads("{}")
    except Exception as e:
        idaapi.msg(f"[Gemida] Gemini request failed: {e}\n")
        return {}
