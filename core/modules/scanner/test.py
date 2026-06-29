import asyncio
from pipeline import osint_and_scan

result = asyncio.run(osint_and_scan("lordfilm7loop.icu"))
print(result["targets"])
print(result["findings"])