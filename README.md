# Discord Security Bot

Author: David Jimenez

This is a cybersecurity bot I developed in Python to protect Discord servers in real time. It works like a firewall, monitoring incoming messages to detect and block common threats like spam and phishing links before they can affect the community.

## Technical Features

* **Admin-Only Commands (RBAC):** Critical commands like checking the system status or unblocking users are locked so only server administrators can run them.
* **Anti-Spam Filter:** The bot tracks how fast users send messages. If someone floods the chat with too many messages in a few seconds, the system automatically isolates them.
* **Phishing Link Detection:** It uses custom regular expressions (RegEx) to instantly catch and delete dangerous links, such as fake Discord Nitro or Steam scams.
* **Smart Local Logging:** To prevent the bot from lagging during heavy chat activity, security events are saved to the local log file in the background using asynchronous code.

## Technical Specifications

* **Language:** Python 3.x
* **Core Library:** Discord.py
* **Configuration:** Python-dotenv (for hiding the secret bot token)

## Core Operations

1. **Message Scanning:** Every single message sent in the server is checked by the bot's background monitor before anything else happens.
2. **Instant Deletion:** When a scam link or heavy spam is detected, the bot deletes the message immediately to protect other users.
3. **Admin Alerts:** The bot sends an ephemeral notification in the chat that only administrators can see, keeping the main channels clean.
4. **User Unblocking:** If a user was isolated by mistake, an admin can run a command to clear their history and restore their permissions.

## Deployment and Execution

Prerequisites: Python 3 installed and proper Gateway Intents enabled in your Discord Developer Portal.

1. Clone the repository: git clone https://github.com/djc1416/discord-security-waf-bot
2. Install dependencies: pip install discord.py python-dotenv
3. Set up environment: Create a local .env file using .env example as a template and paste your DISCORD_TOKEN
4. Run the bot: python main.py