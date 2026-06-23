import os
import re
import time
import asyncio         
from datetime import datetime
import discord
from discord import app_commands
from discord.ext import commands
from dotenv import load_dotenv

# Load secret environment variables
load_dotenv()
TOKEN = os.getenv("DISCORD_TOKEN")

# Configure gateway intents for the bot
intents = discord.Intents.default()
intents.message_content = True
intents.members = True

# --- In-memory database for security analysis 
activity_log = {}
blacklisted_users = set()

# --- Cybersecurity configuration parameters
MAX_MESSAGES = 5        
TIME_WINDOW = 4.0       
PHISHING_REGEX = r"(bit\.ly|t\.co|tinyurl\.com|free-nitro|discord-gift|steampowered-crypto)"

# --- Forensic auditing module (Non-blocking) 
def _write_log(log_entry):
    """Saves the log to disk. Runs inside a separate thread."""
    with open("security_audit.log", "a", encoding="utf-8") as audit_file:
        audit_file.write(log_entry)

async def log_security_event(attack_type, username, user_id, evidence_detail):
    """Prepares the log and schedules non-blocking disk write operations."""
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{current_time}] [ALERT - {attack_type}] User: {username} (ID: {user_id}) | Evidence: {evidence_detail}\n"
    
    # Offload the blocking file write to an executor thread
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, _write_log, log_entry)
    print(f"Security event successfully hard-saved to local logs.")


class SecurityAuditBot(commands.Bot):
    def __init__(self):
        super().__init__(command_prefix="!", intents=intents)

    async def on_ready(self):
        print(f"Cybersecurity Audit WAF System online: {self.user.name}")
        try:
            synced = await self.tree.sync()
            print(f"Successfully synchronized {len(synced)} infrastructure global slash commands.")
        except Exception as e:
            print(f"Error during command synchronization: {e}")

    # Intrusion prevention system (IPS) interceptor
    async def on_message(self, message: discord.Message):
        if message.author == self.user or message.author.bot:
            return

        user_id = message.author.id
        username = message.author.name
        now = time.time()

        if user_id in blacklisted_users:
            try:
                await message.delete()
            except discord.Forbidden:
                pass
            return

        # Rate limiting algorithm (Anti-spam)
        if user_id not in activity_log:
            activity_log[user_id] = []
        
        activity_log[user_id].append(now)
        activity_log[user_id] = [t for t in activity_log[user_id] if now - t < TIME_WINDOW]

        if len(activity_log[user_id]) > MAX_MESSAGES:
            blacklisted_users.add(user_id)
            
            #  Save the security event to logs
            await log_security_event(
                attack_type="RATE_LIMIT_VIOLATION", 
                username=username, 
                user_id=user_id, 
                evidence_detail=f"Flooded {len(activity_log[user_id])} network packets in {TIME_WINDOW}s."
            )

            embed = discord.Embed(
                title="SECURITY ALERT: RATELIMIT BREACH",
                description=f"User {message.author.mention} has been isolated due to data flood anomalies.",
                color=discord.Color.red()
            )
            embed.add_field(name="Breached Metric", value=f"Exceeded {MAX_MESSAGES} messages within {TIME_WINDOW} seconds.")
            
            try:
                await message.channel.send(embed=embed)
            except discord.Forbidden:
                pass
            return

        #  Heuristic content analysis (Phishing)
        if re.search(PHISHING_REGEX, message.content.lower()):
            try:
                await message.delete()
            except discord.Forbidden:
                pass
            
            #  Save the security event to logs
            await log_security_event(
                attack_type="PHISHING_ATTEMPT", 
                username=username, 
                user_id=user_id, 
                evidence_detail=f"Intercepted threat vector: '{message.content}'"
            )

            embed = discord.Embed(
                title="MALICIOUS ENDPOINT BLOCKED",
                description=f"A high-risk phishing attack signature was neutralized from {message.author.mention}.",
                color=discord.Color.orange()
            )
            embed.add_field(name="Sanitized Payload", value=f"||{message.content}||")
            
            try:
                await message.channel.send(embed=embed)
            except discord.Forbidden:
                pass
            return

        await self.process_commands(message)

bot = SecurityAuditBot()

# --- System infrastructure slash commands

@bot.tree.command(name="audit_status", description="Fetches active SOC metrics and current network blacklists.")  
@app_commands.checks.has_permissions(administrator=True)       
async def audit_status(interaction: discord.Interaction):
    embed = discord.Embed(
        title="Security Operations Center (SOC) Console",
        description="Real-time system resilience status.",
        color=discord.Color.blue()
    )
    embed.add_field(name=" Current Isolated Users", value=f"`{len(blacklisted_users)}`", inline=True)
    embed.add_field(name=" Active Firewalls", value="`Rate-Limiting`, `Heuristic-RegEx`, `Hard-Drive Log Persistence`", inline=False)
    
    blacklist_mentions = ", ".join([f"<@{uid}>" for uid in blacklisted_users]) if blacklisted_users else "None"
    embed.add_field(name= "Offender Network IDs", value=blacklist_mentions, inline=False)
    
    await interaction.response.send_message(embed=embed)

@bot.tree.command(name="unblock_user", description="Removes a specific user from the active security blacklist.") 
@app_commands.checks.has_permissions(administrator=True)
@app_commands.describe(user="The server member to lift restrictions from") 
async def unblock_user(interaction: discord.Interaction, user: discord.Member):
    if user.id in blacklisted_users:
        blacklisted_users.remove(user.id)
        if user.id in activity_log:
            activity_log[user.id] = []
        await interaction.response.send_message(f"Security clearances successfully restored for **{user.display_name}**.")
    else:
        await interaction.response.send_message("ℹ Specified network identity holds no active restriction logs.", ephemeral=True)

# --- Global error handler for slash commands
@bot.tree.error
async def on_app_command_error(interaction: discord.Interaction, error: app_commands.AppCommandError):
    if isinstance(error, app_commands.MissingPermissions):
        await interaction.response.send_message(
            "**Access denied:** You do not have Administrator permissions to run this system command.", 
            ephemeral=True
        )
    else:
        print(f"Error no controlado en comando slash: {error}")
        if not interaction.response.is_done():
            await interaction.response.send_message(" An unexpected error occurred while processing the command.", ephemeral=True)

if __name__ == "__main__":
    bot.run(TOKEN)

