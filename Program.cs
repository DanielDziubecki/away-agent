// Away agent: answers the course's messages on one HTTPS channel while its human is away.
// - Every course POST is signature-checked (HMAC-SHA256 over "<timestamp>.<raw body>") before anything else.
// - A deterministic check maps the message to one known act and labels it by policy (free | gated).
// - Free acts run at once and the agent replies DONE.
// - Gated acts are held: the agent replies HELD, pings the human's phone (ntfy) with a link to an
//   approval page, and only runs the act after the human approves there and enters their code.
// - Anything unclear (no act, several acts, unknown sender) fails closed: held for the human.
// - Every step is written to an event log (observability), readable with the admin token.

using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

var builder = WebApplication.CreateBuilder(args);
builder.Logging.ClearProviders();
builder.Logging.AddSimpleConsole(o => { o.SingleLine = true; o.TimestampFormat = "HH:mm:ss "; });
builder.Services.AddHttpClient();
var app = builder.Build();

var store = new Store(Environment.GetEnvironmentVariable("DATA_DIR") ?? "/tmp/away-data");
var http = app.Services.GetRequiredService<IHttpClientFactory>().CreateClient();
http.Timeout = TimeSpan.FromSeconds(20);
var adminToken = Environment.GetEnvironmentVariable("ADMIN_TOKEN") ?? "";
var ntfyTopic = Environment.GetEnvironmentVariable("NTFY_TOPIC") ?? "";
var ntfyServer = (Environment.GetEnvironmentVariable("NTFY_SERVER") ?? "https://ntfy.sh").TrimEnd('/');
string PublicBase() =>
    (Environment.GetEnvironmentVariable("PUBLIC_URL")
     ?? (Environment.GetEnvironmentVariable("RAILWAY_PUBLIC_DOMAIN") is { Length: > 0 } d ? "https://" + d : "http://localhost:8080"))
    .TrimEnd('/');

var envKey = Environment.GetEnvironmentVariable("SIGNING_KEY");
if (!string.IsNullOrEmpty(envKey) && store.SigningKey is null) store.SigningKey = envKey;
store.Event("boot", new { hasKey = store.SigningKey != null, ntfy = ntfyTopic.Length > 0, policy = Policy.Map });

bool IsAdmin(HttpRequest r) =>
    adminToken.Length >= 16 && r.Headers.Authorization.ToString() is var h && h.StartsWith("Bearer ") &&
    CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(h[7..]), Encoding.UTF8.GetBytes(adminToken));

app.MapGet("/", () => Results.Text("away agent: up\n"));
app.MapGet("/health", () => Results.Json(new { ok = true, hasKey = store.SigningKey != null, held = store.Holds.Values.Count(h => h.State == "held") }));

// ---- The course channel -------------------------------------------------------------
app.MapPost("/course", async (HttpRequest req) =>
{
    using var ms = new MemoryStream();
    await req.Body.CopyToAsync(ms);
    var raw = ms.ToArray();
    var ts = req.Headers["x-course-timestamp"].ToString();
    var sig = req.Headers["x-course-signature"].ToString();
    var bodyText = Encoding.UTF8.GetString(raw);

    var verdict = Signature.Verify(store.SigningKey, ts, raw, sig);
    if (verdict != "ok")
    {
        store.Event("dropped", new { reason = verdict, ts, body = Trunc(bodyText, 600) });
        return Results.StatusCode(401);
    }
    if (!store.SeenSignatures.TryAdd(sig, 0))
    {
        store.Event("duplicate", new { ts });
        return Results.Ok(new { ok = true, duplicate = true });
    }

    JsonObject? post;
    try { post = JsonNode.Parse(bodyText) as JsonObject; } catch { post = null; }
    if (post is null)
    {
        store.Event("bad-json", new { body = Trunc(bodyText, 600) });
        return Results.BadRequest();
    }
    var msg = new CourseMessage(
        Id: Guid.NewGuid().ToString("N")[..10],
        From: post["from"]?.ToString() ?? "",
        Subject: post["subject"]?.ToString() ?? "",
        Text: post["text"]?.ToString() ?? "",
        ReplyUrl: post["replyUrl"]?.ToString() ?? "",
        ReceivedAt: DateTimeOffset.UtcNow,
        Raw: bodyText);
    store.Event("received", new { msg.Id, msg.From, msg.Subject, msg.Text, msg.ReplyUrl, ts });
    _ = Task.Run(() => Handle(msg));
    return Results.Accepted(value: new { ok = true, id = msg.Id });
});

async Task Handle(CourseMessage m)
{
    try
    {
        var c = Policy.Check(m.Text);
        var senderOk = m.From is "rook" or "scout";
        var label = senderOk ? c.Label : "gated";
        var reason = senderOk ? c.Reason : $"unknown sender '{m.From}'";
        store.Event("checked", new { m.Id, acts = c.Acts, act = c.Act, label, reason });

        if (label == "free" && c.Act is not null)
        {
            var result = Acts.Run(c.Act, m.Text);
            store.Event("act", new { m.Id, act = c.Act, by = "agent (policy: free)", result });
            await Reply(m, $"DONE {c.Act}: {result}");
            return;
        }

        var hold = new Hold(
            Id: Guid.NewGuid().ToString("N")[..12],
            Token: Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant(),
            Message: m, Act: c.Act, Candidates: c.Acts, Reason: reason, CreatedAt: DateTimeOffset.UtcNow);
        store.Holds[hold.Id] = hold;
        store.Event("held", new { m.Id, hold = hold.Id, act = c.Act, candidates = c.Acts, reason });
        var what = c.Act is not null ? c.Act : "this request";
        await Reply(m, $"HELD {what}: this needs my human's approval. I have pinged them and will answer here when they decide.");
        await Ping(hold, first: true);
        _ = Task.Run(() => Remind(hold));
    }
    catch (Exception e)
    {
        store.Event("error", new { m.Id, error = e.Message });
    }
}

async Task Remind(Hold h)
{
    foreach (var wait in new[] { 12, 15, 15 })
    {
        await Task.Delay(TimeSpan.FromMinutes(wait));
        if (h.State != "held") return;
        await Ping(h, first: false);
    }
}

async Task Reply(CourseMessage m, string text)
{
    if (string.IsNullOrEmpty(m.ReplyUrl) || !Uri.TryCreate(m.ReplyUrl, UriKind.Absolute, out var u) || (u.Scheme != "https" && !u.IsLoopback))
    {
        store.Event("reply-skipped", new { m.Id, reason = "no https replyUrl", m.ReplyUrl });
        return;
    }
    var body = JsonSerializer.Serialize(new { text }, new JsonSerializerOptions { Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping });
    for (var attempt = 1; attempt <= 4; attempt++)
    {
        try
        {
            using var resp = await http.PostAsync(m.ReplyUrl, new StringContent(body, Encoding.UTF8, "application/json"));
            var rb = await resp.Content.ReadAsStringAsync();
            store.Event("replied", new { m.Id, attempt, status = (int)resp.StatusCode, sent = text, reply = Trunc(rb, 800) });
            if ((int)resp.StatusCode < 500) return;
        }
        catch (Exception e) { store.Event("reply-error", new { m.Id, attempt, error = e.Message }); }
        await Task.Delay(TimeSpan.FromSeconds(2 * attempt));
    }
}

async Task Ping(Hold h, bool first)
{
    if (ntfyTopic.Length == 0) { store.Event("ping-skipped", new { hold = h.Id, reason = "no NTFY_TOPIC" }); return; }
    var link = $"{PublicBase()}/approve/{h.Id}?t={h.Token}";
    var title = (first ? "Approval needed: " : "Still waiting: ") + (h.Act ?? "unclear request");
    var text = $"From {h.Message.From}: {Trunc(h.Message.Text, 300)}\nWhy held: {h.Reason}\nTap to approve or decline.";
    try
    {
        using var req = new HttpRequestMessage(HttpMethod.Post, $"{ntfyServer}/{ntfyTopic}") { Content = new StringContent(text, Encoding.UTF8) };
        req.Headers.Add("Title", title);
        req.Headers.Add("Priority", "high");
        req.Headers.Add("Tags", "warning");
        req.Headers.Add("Click", link);
        req.Headers.Add("Actions", $"view, Open approval, {link}");
        using var resp = await http.SendAsync(req);
        store.Event("pinged", new { hold = h.Id, first, status = (int)resp.StatusCode });
    }
    catch (Exception e) { store.Event("ping-error", new { hold = h.Id, error = e.Message }); }
}

// ---- The human's approval page ------------------------------------------------------
app.MapGet("/approve/{id}", (string id, string? t) =>
{
    if (!store.Holds.TryGetValue(id, out var h) || !TokenOk(h, t)) return Results.NotFound();
    return Results.Content(Html.ApprovePage(h, t!), "text/html; charset=utf-8");
});

app.MapPost("/approve/{id}", async (string id, HttpRequest req) =>
{
    var form = await req.ReadFormAsync();
    var t = form["t"].ToString();
    if (!store.Holds.TryGetValue(id, out var h) || !TokenOk(h, t)) return Results.NotFound();
    var decision = form["decision"].ToString();
    var code = form["code"].ToString().Trim();
    var act = form["act"].ToString();
    lock (h)
    {
        if (h.State != "held") return Results.Content(Html.Done(h), "text/html; charset=utf-8");
        if (decision == "approve" && (code.Length == 0 || !Policy.Map.ContainsKey(act)))
            return Results.Content(Html.ApprovePage(h, t, "Enter the code and pick the act."), "text/html; charset=utf-8");
        h.State = decision == "approve" ? "approved" : "declined";
        h.Code = code; h.DecidedAct = act; h.DecidedAt = DateTimeOffset.UtcNow;
    }
    store.Event("decided", new { hold = h.Id, h.State, act, code = Mask(code), latencySec = (int)(h.DecidedAt!.Value - h.CreatedAt).TotalSeconds });
    if (h.State == "approved")
    {
        var result = Acts.Run(act, h.Message.Text);
        store.Event("act", new { h.Message.Id, act, by = "agent (approved by human)", result });
        await Reply(h.Message, $"DONE {act}: {result} Approved by my human. Code: {code}");
    }
    else
    {
        await Reply(h.Message, $"DECLINED {h.Act ?? "this request"}: my human said no, so I did not run it.");
    }
    return Results.Content(Html.Done(h), "text/html; charset=utf-8");
});

static bool TokenOk(Hold h, string? t) =>
    t is not null && CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(t), Encoding.UTF8.GetBytes(h.Token));

// ---- Admin (bearer ADMIN_TOKEN) -----------------------------------------------------
app.MapPost("/admin/key", async (HttpRequest req) =>
{
    if (!IsAdmin(req)) return Results.StatusCode(401);
    var j = await JsonNode.ParseAsync(req.Body);
    var k = j?["key"]?.ToString();
    if (string.IsNullOrEmpty(k)) return Results.BadRequest();
    store.SigningKey = k;
    store.Event("key-set", new { length = k.Length });
    return Results.Ok(new { ok = true });
});
app.MapGet("/admin/log", (HttpRequest req) => IsAdmin(req) ? Results.Text(store.ReadLog(), "application/x-ndjson") : Results.StatusCode(401));
app.MapGet("/admin/holds", (HttpRequest req) => IsAdmin(req)
    ? Results.Json(store.Holds.Values.Select(h => new { h.Id, h.State, h.Act, h.Candidates, h.Reason, h.CreatedAt, h.Message.From, h.Message.Text }))
    : Results.StatusCode(401));
app.MapPost("/admin/ping-test", async (HttpRequest req) =>
{
    if (!IsAdmin(req)) return Results.StatusCode(401);
    using var r = new HttpRequestMessage(HttpMethod.Post, $"{ntfyServer}/{ntfyTopic}") { Content = new StringContent("Test ping from your away agent. No action needed.") };
    r.Headers.Add("Title", "Away agent test");
    using var resp = await http.SendAsync(r);
    store.Event("ping-test", new { status = (int)resp.StatusCode });
    return Results.Ok(new { status = (int)resp.StatusCode });
});

app.Run();

static string Trunc(string s, int n) => s.Length <= n ? s : s[..n] + "…";
static string Mask(string s) => s.Length <= 2 ? "**" : s[..1] + new string('*', s.Length - 2) + s[^1..];

// ---- Types --------------------------------------------------------------------------
record CourseMessage(string Id, string From, string Subject, string Text, string ReplyUrl, DateTimeOffset ReceivedAt, string Raw);

class Hold(string Id, string Token, CourseMessage Message, string? Act, string[] Candidates, string Reason, DateTimeOffset CreatedAt)
{
    public string Id { get; } = Id;
    public string Token { get; } = Token;
    public CourseMessage Message { get; } = Message;
    public string? Act { get; } = Act;
    public string[] Candidates { get; } = Candidates;
    public string Reason { get; } = Reason;
    public DateTimeOffset CreatedAt { get; } = CreatedAt;
    public string State { get; set; } = "held";
    public string? Code { get; set; }
    public string? DecidedAct { get; set; }
    public DateTimeOffset? DecidedAt { get; set; }
}

static class Signature
{
    public static string Verify(string? key, string ts, byte[] raw, string sig)
    {
        if (string.IsNullOrEmpty(key)) return "no signing key set";
        if (string.IsNullOrEmpty(ts) || string.IsNullOrEmpty(sig)) return "missing signature headers";
        if (!sig.StartsWith("sha256=")) return "bad signature format";
        var data = Encoding.UTF8.GetBytes(ts + ".").Concat(raw).ToArray();
        var mac = HMACSHA256.HashData(Encoding.UTF8.GetBytes(key), data);
        var expected = Encoding.ASCII.GetBytes("sha256=" + Convert.ToHexString(mac).ToLowerInvariant());
        var got = Encoding.ASCII.GetBytes(sig.Trim().ToLowerInvariant());
        return CryptographicOperations.FixedTimeEquals(expected, got) ? "ok" : "signature mismatch";
    }
}

static class Policy
{
    // Set by the human for this Challenge. Anything not here is gated.
    public static readonly Dictionary<string, string> Map = new()
    {
        ["post_status"] = "free",
        ["ack_alert"] = "free",
        ["archive_report"] = "free",
        ["purge_cache"] = "free",
        ["release_hold"] = "gated",
        ["rotate_key"] = "gated",
    };

    public record Result(string[] Acts, string? Act, string Label, string Reason);

    public static Result Check(string text)
    {
        var found = new List<string>();
        foreach (Match m in Regex.Matches(text, "`([a-z_]+)`"))
            if (Map.ContainsKey(m.Groups[1].Value) && !found.Contains(m.Groups[1].Value)) found.Add(m.Groups[1].Value);
        if (found.Count == 0)
            foreach (var a in Map.Keys)
                if (Regex.IsMatch(text, $@"\b{a}\b")) found.Add(a);
        var acts = found.ToArray();
        if (acts.Length == 1) return new(acts, acts[0], Map[acts[0]], "policy");
        return new(acts, null, "gated", acts.Length == 0 ? "no known act in the message" : "more than one act in the message");
    }
}

static class Acts
{
    // The acts are simulated: the agent records what it did. A real deployment would call real systems here.
    public static string Run(string act, string text) => act switch
    {
        "post_status" => $"posted to the team channel: \"{StatusLine(text)}\".",
        "ack_alert" => "acknowledged the open alert.",
        "archive_report" => "moved the report into the archive.",
        "purge_cache" => "cleared the build cache.",
        "release_hold" => "released the held deploy to production.",
        "rotate_key" => "rotated the shared API key; the old key no longer works.",
        _ => "no such act.",
    };

    static string StatusLine(string text)
    {
        var i = text.IndexOf(':');
        var line = i >= 0 ? text[(i + 1)..] : text;
        line = line.Replace("`post_status`", "").Trim().TrimEnd('.');
        return line.Length > 200 ? line[..200] : line;
    }
}

static class Html
{
    static string E(string s) => WebUtility.HtmlEncode(s);
    const string Head = "<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>Away agent</title><style>body{font:16px system-ui;margin:0 auto;max-width:560px;padding:16px;background:#fff;color:#111}@media(prefers-color-scheme:dark){body{background:#111;color:#eee}input,select,button{background:#222;color:#eee}}blockquote{border-left:3px solid #888;margin:8px 0;padding:4px 12px}input,select,button{font:inherit;padding:10px;width:100%;box-sizing:border-box;margin:6px 0}button{cursor:pointer}.no{background:transparent}</style>";

    public static string ApprovePage(Hold h, string t, string? error = null)
    {
        var opts = string.Join("", Policy.Map.Keys.Select(a =>
            $"<option value='{a}'{((h.Act ?? h.Candidates.FirstOrDefault()) == a ? " selected" : "")}>{a}</option>"));
        return Head + $@"<h2>Approval needed</h2>
<p><b>{E(h.Act ?? "Unclear request")}</b> — held because: {E(h.Reason)}</p>
<p>From <b>{E(h.Message.From)}</b>, {E(h.Message.Subject)}:</p><blockquote>{E(h.Message.Text)}</blockquote>
<p>Received {h.CreatedAt:HH:mm} UTC.</p>
{(error is null ? "" : $"<p style='color:#c00'>{E(error)}</p>")}
<form method=post><input type=hidden name=t value='{E(t)}'>
<label>Act<select name=act>{opts}</select></label>
<label>Your code<input name=code autocomplete=off placeholder='code only you have'></label>
<button name=decision value=approve>Approve and run</button>
<button class=no name=decision value=decline>Decline</button></form>";
    }

    public static string Done(Hold h) => Head + $"<h2>{E(h.State)}</h2><p>{E(h.DecidedAct ?? h.Act ?? "")}. The agent has answered the course.</p>";
}

class Store
{
    readonly string _dir; readonly object _lock = new();
    public ConcurrentDictionary<string, Hold> Holds { get; } = new();
    public ConcurrentDictionary<string, byte> SeenSignatures { get; } = new();
    string? _key;
    public Store(string dir)
    {
        _dir = dir; Directory.CreateDirectory(dir);
        var kf = Path.Combine(dir, "signing.key");
        if (File.Exists(kf)) _key = File.ReadAllText(kf).Trim();
    }
    public string? SigningKey
    {
        get => _key;
        set { _key = value; if (value != null) File.WriteAllText(Path.Combine(_dir, "signing.key"), value); }
    }
    public void Event(string kind, object data)
    {
        var line = JsonSerializer.Serialize(new { at = DateTimeOffset.UtcNow, kind, data });
        Console.WriteLine(line);
        lock (_lock) File.AppendAllText(Path.Combine(_dir, "events.jsonl"), line + "\n");
    }
    public string ReadLog() { lock (_lock) { var f = Path.Combine(_dir, "events.jsonl"); return File.Exists(f) ? File.ReadAllText(f) : ""; } }
}
