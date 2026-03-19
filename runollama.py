from ollama import chat
from ollama import ChatResponse
import json

print("Starting Ollama request...")
print("Model: gemma3")

messages = [
    {
        "role": "user",
        "content": "dont ask me any questions just do what i ask you okay? say blabla 100 times"
    }
]

print("\nMessages being sent:")
print(json.dumps(messages, indent=2))

print("\nSending request to Ollama...\n")

response: ChatResponse = chat(
    model="gemma3",
    messages=messages
)

print("\n========== RAW RESPONSE OBJECT ==========")
print(response)

print("\n========== RESPONSE AS DICTIONARY ==========")
print(json.dumps(response.dict(), indent=2))

print("\n========== MODEL OUTPUT ==========")
print(response.message.content)

print("\n========== SCRIPT COMPLETE ==========")
