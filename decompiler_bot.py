import os
import subprocess
import logging
import asyncio
import shutil
import time
from datetime import datetime
from telegram import Update, Bot
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, filters, ContextTypes

# Import our decompiler tool
from decompiler_tool import analyze_python_script

# Configuration
TOKEN = "7828849465:AAGYuFRbWrbIY9TOTDG5Xy023OWXaBQdLFI"
SAVE_DIR = "./uploads"
RESULTS_DIR = "./decompiled_payloads"
LOG_DIR = "./logs"
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB max file size

# Create directories
os.makedirs(SAVE_DIR, exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

# Set up logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO,
    filename=os.path.join(LOG_DIR, f"bot_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
)
logger = logging.getLogger("DecompilerBot")

# --- Command Handlers ---
async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Send a welcome message when the /start command is issued."""
    help_message = (
        "Welcome to the Python Decompiler Bot!\n\n"
        "This bot analyzes Python files (.py) for potentially malicious code, "
        "decompiles obfuscated content, and extracts encoded payloads.\n\n"
        "Simply send a Python file to begin analysis.\n\n"
        "Commands:\n"
        "/start - Show this help message\n"
        "/help - Show this help message\n"
        "/status - Check bot status"
    )
    await update.message.reply_text(help_message)

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Send help message."""
    await start_command(update, context)

async def status_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Check the bot status."""
    status_message = (
        "✅ Bot is operational\n"
        f"📁 Upload directory: {len(os.listdir(SAVE_DIR))} files\n"
        f"📊 Results directory: {len(os.listdir(RESULTS_DIR))} files\n"
        f"📝 Log directory: {len(os.listdir(LOG_DIR))} files\n"
    )
    await update.message.reply_text(status_message)

# --- File Handler ---
async def handle_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle uploaded Python files."""
    # Check if message contains a document
    if not update.message.document:
        await update.message.reply_text("Please send a Python file (.py) to analyze.")
        return

    doc = update.message.document
    file_name = doc.file_name
    user_id = update.effective_user.id
    chat_id = update.effective_chat.id
    
    # Log the upload
    logger.info(f"Received file: {file_name} from user {user_id}")
    
    # Check file extension
    if not file_name.endswith(".py"):
        await update.message.reply_text("Only Python (.py) files are supported.")
        return
    
    # Check file size
    if doc.file_size > MAX_FILE_SIZE:
        await update.message.reply_text(f"File is too large. Maximum size is {MAX_FILE_SIZE/1024/1024} MB.")
        return
    
    # Create a unique session ID for this analysis
    session_id = f"{user_id}_{int(time.time())}"
    session_dir = os.path.join(RESULTS_DIR, session_id)
    os.makedirs(session_dir, exist_ok=True)
    
    # Download the file
    file_path = os.path.join(SAVE_DIR, f"{session_id}_{file_name}")
    new_file = await doc.get_file()
    await new_file.download_to_drive(file_path)
    
    # Inform user
    await update.message.reply_text(
        f"✅ Received file: {file_name}\n"
        f"🔍 Starting analysis...\n"
        f"🆔 Session ID: {session_id}"
    )
    
    # Start analysis in a separate task
    asyncio.create_task(analyze_file_task(update, context, file_path, session_dir, session_id))

async def analyze_file_task(update: Update, context: ContextTypes.DEFAULT_TYPE, file_path: str, 
                           session_dir: str, session_id: str):
    """Analyze the file in a separate task."""
    try:
        # Check if file exists
        if not os.path.exists(file_path):
            await update.message.reply_text("❌ Error: File not found.")
            return
            
        # Send in-progress notification
        progress_message = await update.message.reply_text("⏳ Analysis in progress...")
        
        # Run the analysis
        report_path, extracted_files = analyze_python_script(file_path, session_dir)
        
        # Update progress
        await context.bot.edit_message_text(
            chat_id=update.effective_chat.id,
            message_id=progress_message.message_id,
            text="✅ Analysis complete, sending results..."
        )
        
        # Send the analysis report
        with open(report_path, 'r') as report_file:
            report_content = report_file.read()
        
        # If report is too long, send as a file instead
        if len(report_content) > 4000:
            await update.message.reply_document(
                document=open(report_path, 'rb'),
                filename=os.path.basename(report_path),
                caption="📊 Analysis Report"
            )
        else:
            await update.message.reply_text(
                f"📊 Analysis Report:\n\n```\n{report_content}\n```",
                parse_mode="Markdown"
            )
        
        # Send extracted files
        for file_path in extracted_files:
            # Skip the report file as we already sent it
            if file_path == report_path:
                continue
                
            # Send the file
            try:
                await update.message.reply_document(
                    document=open(file_path, 'rb'),
                    filename=os.path.basename(file_path)
                )
            except Exception as e:
                logger.error(f"Failed to send file {file_path}: {str(e)}")
                await update.message.reply_text(f"❌ Failed to send {os.path.basename(file_path)}: {str(e)}")
        
        # Final status message
        await update.message.reply_text(
            f"✅ Analysis completed successfully.\n"
            f"📁 Session ID: {session_id}\n"
            f"📊 Files extracted: {len(extracted_files)}"
        )
        
    except Exception as e:
        logger.error(f"Error analyzing file: {str(e)}", exc_info=True)
        await update.message.reply_text(f"❌ Error during analysis: {str(e)}")
    finally:
        # Clean up
        cleanup(file_path)

# --- Optional Sandbox Implementation ---
class Sandbox:
    """Simple sandbox implementation using subprocess."""
    
    @staticmethod
    async def run_script_safely(script_path: str, timeout: int = 10) -> dict:
        """
        Run a Python script in a sandboxed environment with timeout.
        
        Args:
            script_path: Path to the Python script
            timeout: Timeout in seconds
            
        Returns:
            Dictionary with stdout, stderr, and execution time
        """
        start_time = time.time()
        
        try:
            # Create a sandbox command using Python's subprocess
            process = await asyncio.create_subprocess_exec(
                "python", "-c",
                f"import sys; sys.path.insert(0, '.'); "
                f"import os; os.chdir(os.path.dirname('{script_path}')); "
                f"try: exec(open('{os.path.basename(script_path)}').read()); "
                f"except Exception as e: print(f'Error: {{e}}', file=sys.stderr)",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Wait for the process to complete (with timeout)
            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
                stdout = stdout.decode('utf-8', errors='ignore')
                stderr = stderr.decode('utf-8', errors='ignore')
            except asyncio.TimeoutError:
                process.kill()
                stdout = ""
                stderr = "Execution timed out"
            
            execution_time = time.time() - start_time
            
            return {
                "stdout": stdout,
                "stderr": stderr,
                "execution_time": execution_time,
                "timed_out": execution_time >= timeout
            }
            
        except Exception as e:
            return {
                "stdout": "",
                "stderr": f"Error in sandbox: {str(e)}",
                "execution_time": time.time() - start_time,
                "timed_out": False
            }

# --- Cleanup ---
def cleanup(file_path: str = None):
    """Clean up temporary files."""
    if file_path and os.path.exists(file_path):
        try:
            os.remove(file_path)
        except Exception as e:
            logger.error(f"Failed to remove file {file_path}: {str(e)}")

# --- Main Bot Setup ---
async def main():
    """Start the bot."""
    # Create application
    app = ApplicationBuilder().token(TOKEN).build()
    
    # Add handlers
    app.add_handler(CommandHandler("start", start_command))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("status", status_command))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_file))
    
    # Start the bot
    logger.info("Bot started")
    print("[+] Bot is running...")
    await app.run_polling()

if __name__ == "__main__":
    asyncio.run(main())