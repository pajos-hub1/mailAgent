"""
Minimal main.py that uses the CLI interface
"""
import asyncio
from cli.email_cli import main

if __name__ == "__main__":
    asyncio.run(main())
