import openai
import os
openai.api_key = os.getenv("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")

models = openai.Model.list()
for m in models['data']:
    print(m['id'])
