import asyncio

from .pipeline import osint_and_scan


async def main() -> None:
    result = await osint_and_scan("lordfilm7loop.icu")
    print(result["targets"])
    print(result["findings"])


if __name__ == "__main__":
    asyncio.run(main())
