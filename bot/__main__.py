from pyrogram import filters
from bot import app, data, sudo_users, cc
from bot.helper.utils import add_task
from pyrogram import types
from bot import (
    data,
    crf,
    watermark
)

@app.on_message(filters.incoming & filters.command(['start', 'help']))
def help_message(app, message):
    message.reply_text(f"Hey {message.from_user.mention()} 💙.", quote=True)

@app.on_message(filters.user(sudo_users) & filters.incoming & (filters.video | filters.document))
def encode_video(app, message):
    if message.document:
     message.reply_text("Added To Queue⏲️\n Please Be Patient", quote=True) 
    data.append(message)
    if len(data) == 1:
      add_task(message)
@app.on_message(filters.user(sudo_users))
def sudo(app, message):
    message.reply_text(f"•••••HELP••••• \n Ω Send any file to check it \n Ω Toggle coming soon\n Ω Current checker" + cc)




app.run()
