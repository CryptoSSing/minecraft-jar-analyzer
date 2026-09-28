"""Reference data used by the indicator rules.

This file is deliberately *just data* so it can be reviewed and extended
without reading any logic. Matching is case-insensitive unless noted.
Being on one of these lists is evidence to look at - never proof.
"""

# --------------------------------------------------------------------------
# Popular mods and plugins. Used to spot look-alike IDs ("sodiurn") that may be
# impersonating a well-known project. Exact matches are NOT flagged as
# suspicious; they just get a reminder to verify the download source.
# --------------------------------------------------------------------------
POPULAR_MOD_IDS = {
    # Performance / rendering
    "sodium", "lithium", "iris", "indium", "phosphor", "starlight", "ferritecore",
    "entityculling", "modernfix", "immediatelyfast", "c2me", "krypton", "lazydfu",
    "dynamicfps", "sodiumextra", "reesessodiumoptions", "continuity", "lambdynlights",
    "optifine", "optifabric", "embeddium", "rubidium", "oculus", "memoryleakfix",
    # Libraries / APIs
    "fabricapi", "fabric", "fabriclanguagekotlin", "kotlinforforge", "architectury",
    "clothconfig", "yetanotherconfiglib", "geckolib", "curios", "trinkets", "balm",
    "patchouli", "puzzleslib", "citadel", "moonlight", "creativecore", "cloth",
    # Utility / UI
    "modmenu", "jei", "roughlyenoughitems", "emi", "jade", "wthit", "journeymap",
    "xaerominimap", "xaeroworldmap", "appleskin", "mousetweaks", "controlling",
    "inventoryprofilesnext", "betterf3", "zoomify", "voicechat", "replaymod",
    "essential", "worldedit", "litematica", "minihud", "tweakeroo", "malilib",
    # Content
    "create", "botania", "ae2", "appliedenergistics2", "mekanism", "twilightforest",
    "biomesoplenty", "terralith", "waystones", "farmersdelight", "supplementaries",
    "quark", "alexsmobs", "sophisticatedbackpacks", "storagedrawers", "ironchests",
    "tconstruct", "ftbquests", "ftblibrary", "kubejs", "travelersbackpack",
    # Server plugins (plugin.yml "name")
    "luckperms", "essentials", "essentialsx", "vault", "protocollib", "placeholderapi",
    "viaversion", "viabackwards", "geyser", "floodgate", "citizens", "worldguard",
    "multiversecore", "coreprotect", "discordsrv", "griefprevention", "skript",
}

# --------------------------------------------------------------------------
# Domains
# --------------------------------------------------------------------------

# Well-known, widely used domains. URLs here are listed as INFO for transparency.
KNOWN_DOMAINS = {
    "github.com", "githubusercontent.com", "github.io", "gitlab.com", "bitbucket.org",
    "modrinth.com", "curseforge.com", "curse.com", "forgecdn.net",
    "minecraft.net", "mojang.com", "minecraftservices.com", "minecraft.wiki",
    "fabricmc.net", "quiltmc.org", "neoforged.net", "minecraftforge.net",
    "spongepowered.org", "spigotmc.org", "papermc.io", "bukkit.org", "bstats.org",
    "apache.org", "w3.org", "xml.org", "json-schema.org", "schema.org", "java.com",
    "oracle.com", "openjdk.org", "sun.com", "kotlinlang.org", "jetbrains.com",
    "gnu.org", "opensource.org", "creativecommons.org", "sonatype.org", "maven.org",
    "google.com", "youtube.com", "youtu.be", "twitter.com", "x.com", "reddit.com",
    "wikipedia.org", "patreon.com", "ko-fi.com", "paypal.com", "paypal.me",
    "discord.gg", "discord.com", "discordapp.com", "crowdin.com", "twitch.tv",
    "microsoft.com", "live.com", "xboxlive.com", "mozilla.org", "slf4j.org", "logback.qos.ch",
}

# Pastebins / raw-text hosts: often used to host a second-stage URL or payload.
PASTE_DOMAINS = {
    "pastebin.com", "hastebin.com", "paste.ee", "rentry.co", "rentry.org",
    "ghostbin.com", "controlc.com", "privatebin.net", "pastes.dev", "paste.gg",
}

# Tunnels and dynamic-DNS services: let a home PC act as a server, commonly
# used for command-and-control servers.
TUNNEL_DOMAINS = {
    "ngrok.io", "ngrok-free.app", "ngrok.app", "trycloudflare.com", "duckdns.org",
    "ddns.net", "hopto.org", "no-ip.org", "no-ip.com", "serveo.net", "loca.lt",
    "portmap.io", "portmap.host",
}

# Anonymous file-sharing hosts: commonly used to host downloaded payloads.
FILE_HOST_DOMAINS = {
    "transfer.sh", "file.io", "gofile.io", "anonfiles.com", "catbox.moe",
    "litter.catbox.moe", "mega.nz", "mediafire.com", "sendspace.com", "filebin.net",
}

URL_SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "is.gd", "cutt.ly", "t.ly", "rb.gy", "shorturl.at", "goo.gl",
}

# Services that tell a program its public IP address / location.
IP_LOOKUP_DOMAINS = {
    "ipify.org", "ip-api.com", "ipinfo.io", "icanhazip.com", "checkip.amazonaws.com",
    "ifconfig.me", "myexternalip.com", "wtfismyip.com",
}

# Free top-level domains historically popular for throwaway malicious sites.
FREE_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq"}

# URL fragments that indicate a data-exfiltration channel.
# Checked with a simple "fragment in url" test.
EXFIL_URL_FRAGMENTS = {
    "discord.com/api/webhooks": "Discord webhook",
    "discordapp.com/api/webhooks": "Discord webhook",
    "canary.discord.com/api/webhooks": "Discord webhook",
    "ptb.discord.com/api/webhooks": "Discord webhook",
    "api.telegram.org/bot": "Telegram bot API",
}

# --------------------------------------------------------------------------
# Sensitive strings. Each maps a text fragment to a category. These are paths
# and names that credential stealers look for. Legitimate mods essentially
# never need them.
# --------------------------------------------------------------------------
CATEGORY_DISCORD = "Discord token storage"
CATEGORY_BROWSER = "Browser credential/cookie storage"
CATEGORY_WALLET = "Cryptocurrency wallet"
CATEGORY_LAUNCHER = "Minecraft launcher account files"
CATEGORY_PERSISTENCE = "Startup persistence"
CATEGORY_DEFENDER = "Antivirus tampering"
CATEGORY_MINER = "Cryptocurrency mining"
CATEGORY_DPAPI = "Windows credential decryption"
CATEGORY_SHELL = "Command shell"

SENSITIVE_STRINGS = {
    # Discord keeps login tokens in LevelDB files under "Local Storage".
    "discordcanary": CATEGORY_DISCORD,
    "discordptb": CATEGORY_DISCORD,
    "local storage\\leveldb": CATEGORY_DISCORD,
    "local storage/leveldb": CATEGORY_DISCORD,
    "dqw4w9wgxcq:": CATEGORY_DISCORD,  # prefix of Discord's encrypted tokens
    # Chromium / Firefox browser data.
    "login data": CATEGORY_BROWSER,
    "\\google\\chrome\\user data": CATEGORY_BROWSER,
    "/google/chrome/user data": CATEGORY_BROWSER,
    "bravesoftware": CATEGORY_BROWSER,
    "opera software": CATEGORY_BROWSER,
    "mozilla\\firefox\\profiles": CATEGORY_BROWSER,
    "logins.json": CATEGORY_BROWSER,
    "key4.db": CATEGORY_BROWSER,
    "encrypted_key": CATEGORY_BROWSER,
    # Wallets.
    "wallet.dat": CATEGORY_WALLET,
    "exodus.wallet": CATEGORY_WALLET,
    "electrum\\wallets": CATEGORY_WALLET,
    "nkbihfbeogaeaoehlefnkodbefgpgknn": CATEGORY_WALLET,  # MetaMask extension ID
    # Launcher account/token files. Only specific FILE paths are listed: plain
    # launcher names ("prismlauncher") also appear in legitimate mods that
    # detect the launcher, e.g. to show troubleshooting help.
    "launcher_accounts.json": CATEGORY_LAUNCHER,
    "launcher_accounts_microsoft_store.json": CATEGORY_LAUNCHER,
    "microsoft_accounts.json": CATEGORY_LAUNCHER,
    "settings/game/accounts.json": CATEGORY_LAUNCHER,   # Lunar Client
    "settings\\game\\accounts.json": CATEGORY_LAUNCHER,
    "prismlauncher/accounts.json": CATEGORY_LAUNCHER,
    "prismlauncher\\accounts.json": CATEGORY_LAUNCHER,
    "polymc/accounts.json": CATEGORY_LAUNCHER,
    "multimc/accounts.json": CATEGORY_LAUNCHER,
    "feather/accounts.json": CATEGORY_LAUNCHER,
    "tlauncheradditional.json": CATEGORY_LAUNCHER,
    # Persistence (run again at every login).
    "\\start menu\\programs\\startup": CATEGORY_PERSISTENCE,
    "currentversion\\run": CATEGORY_PERSISTENCE,
    "schtasks": CATEGORY_PERSISTENCE,
    "launchagents": CATEGORY_PERSISTENCE,
    # Disabling or excluding antivirus scanning.
    "add-mppreference": CATEGORY_DEFENDER,
    "set-mppreference": CATEGORY_DEFENDER,
    "exclusionpath": CATEGORY_DEFENDER,
    # Miners.
    "stratum+tcp://": CATEGORY_MINER,
    "xmrig": CATEGORY_MINER,
    # Windows DPAPI decryption (used to decrypt saved browser passwords).
    "cryptunprotectdata": CATEGORY_DPAPI,
    # Shells (moderate signal on their own).
    "cmd.exe": CATEGORY_SHELL,
    "powershell": CATEGORY_SHELL,
    "/bin/sh": CATEGORY_SHELL,
    "/bin/bash": CATEGORY_SHELL,
}

# Categories strong enough to be a WARNING by themselves.
HIGH_RISK_CATEGORIES = {
    CATEGORY_DISCORD, CATEGORY_BROWSER, CATEGORY_WALLET, CATEGORY_LAUNCHER,
    CATEGORY_PERSISTENCE, CATEGORY_DEFENDER, CATEGORY_MINER, CATEGORY_DPAPI,
}

# Member names used to read the logged-in player's Minecraft session token
# (Mojang names / Fabric intermediary / legacy Forge SRG names). Only counted
# when called on a Minecraft class (other libraries have their own
# "getSessionId"). Account switchers and some auth mods use these
# legitimately; stealers use them too.
SESSION_TOKEN_MEMBERS = {
    "getAccessToken",   # Mojang mappings (User/Session)
    "getSessionId",
    "method_1674",      # Fabric intermediary: Session.getAccessToken
    "func_148254_d",    # legacy Forge SRG: Session.getToken
    "func_111286_b",    # legacy Forge SRG: Session.getSessionID
}

# --------------------------------------------------------------------------
# Class-name patterns
# --------------------------------------------------------------------------

# Words in class/resource names associated with malware tooling.
MALWARE_NAME_WORDS = [
    "stealer", "grabber", "keylog", "backdoor", "exfil", "tokenlog",
    "tokengrab", "clipper", "cryptominer", "webhook", "ratclient",
]

# Words in class names associated with gameplay-advantage features that many
# servers prohibit. This is about server rules, not malware.
CHEAT_FEATURE_WORDS = [
    "killaura", "aimbot", "triggerbot", "autoclicker", "crystalaura", "autocrystal",
    "anchoraura", "bedaura", "autototem", "nofall", "antiknockback", "xray",
    "nuker", "fastbreak", "speedmine", "noslow", "elytrafly", "boatfly",
]

# Package prefixes of well-known utility/cheat clients.
KNOWN_CLIENT_PACKAGES = {
    "meteordevelopment/meteorclient/": "Meteor Client",
    "net/wurstclient/": "Wurst Client",
    "net/ccbluex/liquidbounce/": "LiquidBounce",
    "me/zeroeightsix/kami/": "KAMI",
    "org/rusherhack/": "RusherHack",
    "baritone/": "Baritone (automation/pathfinding bot)",
}

# Namespaces owned by Java or Minecraft. A mod defining its own classes here
# is unusual (OptiFine and some legacy mods do it legitimately).
RESERVED_PACKAGES = ["java/", "sun/", "jdk/", "net/minecraft/", "com/mojang/"]
