import os

print(f"OPENAI_API_KEY={os.getenv('OPENAI_API_KEY')}")
logger.info("Authorization: Bearer %s", os.getenv("ANTHROPIC_API_KEY"))
