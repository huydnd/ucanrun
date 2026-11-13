# Approval channels

ucanrun sends each request to every paired channel; you can approve or deny
from any of them, or on the web. Set them up under **Settings → Approval
channels**.

| Channel | How it reaches ucanrun | Approve | TOTP |
|---|---|---|---|
| Telegram | ucanrun polls Telegram | button | send the code as a message |
| Discord | Discord calls `/hooks/discord` | button | a form opens |
| LINE | LINE calls `/hooks/line` | button | send the code as a message |
| WhatsApp | Meta calls `/hooks/whatsapp` | button | send the code as a message |

Discord, LINE and WhatsApp call ucanrun, so the server needs a public HTTPS
address (`UCANRUN_PUBLIC_URL`). The settings page shows the webhook URL to
paste on the platform's side.

## Security

- `/hooks/...` skip the access gate, because the platforms cannot know the
  access code. Each call must carry the platform's signature, checked before
  the body is read: Discord ed25519 with the application's public key (and a
  timestamp under five minutes old), LINE HMAC-SHA256 with the channel secret,
  WhatsApp HMAC-SHA256 with the app secret. Unsigned or wrongly signed calls
  get 401; a channel that is not set up gets 404.
- Only the paired account can decide. Everyone else gets no answer (Discord
  answers "no permission", since it requires an answer).
- Pairing uses the same single-use code as Telegram: three minutes, three
  tries. A new setup clears the pairing.
- Tokens and secrets are kept in the vault (`_chat_<kind>`), never shown again.
- Messages are plain text; Discord messages mention nobody.

## Discord

1. At discord.com/developers/applications, create an application. Under
   **Bot**, press **Reset Token** and paste the token in ucanrun. ucanrun reads
   the application id and public key and registers the `/pair` command.
2. Paste the webhook URL into **General Information → Interactions Endpoint
   URL**. Discord checks it right away.
3. Under **Installation**, turn on **User Install**, or invite the bot to a
   server you are in, so you can message it privately.
4. In a private message to the bot: `/pair code:<code>`.

## LINE

1. At developers.line.biz, create a **Messaging API** channel.
2. Paste the long-lived **Channel access token** and the **Channel secret**.
3. Paste the webhook URL into **Messaging API → Webhook settings**, turn on
   **Use webhook**, and turn off **Auto-reply messages**.
4. Add the bot as a friend and send `/pair <code>`.

LINE cannot edit sent messages, so the result arrives as a new message.

## WhatsApp

1. At developers.facebook.com, create an app with the **WhatsApp** product.
2. Paste an access token that does not expire (a System User token), the
   **Phone number ID**, and the **App secret** (App settings → Basic).
3. Paste the webhook URL and the **Verify token** ucanrun shows into
   **WhatsApp → Configuration**, and subscribe to `messages`.
4. From your phone, send `/pair <code>` to the business number.

WhatsApp delivers free text only within 24 hours of your last message to the
number. Outside that window the request still waits on the web; send the bot
any message to open the window again.
