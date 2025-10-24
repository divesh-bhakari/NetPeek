# test_gemini_models_v2.py

from google import genai
import os

# --- Configure client ---
client = genai.Client(api_key="YOUR_GEMINI_API_KEY_HERE")  # Or use os.getenv("GOOGLE_API_KEY")

print("\n✅ Gemini SDK Connected Successfully!")
print("🔍 Listing available models that support generateContent...\n")

try:
    models = client.models.list()

    for model in models:
        # Some SDK versions expose supported methods differently
        methods = getattr(model, "supported_methods", "unknown")
        print(f"Model: {model.name}")
        print(f"Supported methods: {methods}")
        print("-" * 60)

except Exception as e:
    print("❌ Error while listing models:", e)
