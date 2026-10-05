import { createFileRoute } from "@tanstack/react-router";
import { useChat } from "@ai-sdk/react";
import { DefaultChatTransport, type UIMessage } from "ai";
import { useEffect, useRef, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";
import {
  Bell, BellOff, Lock, Unlock, Link2, Mail, Paperclip, ArrowUp, ShieldCheck,
  PanelRightClose, PanelRightOpen, Trash2, Pin, PinOff, Square, KeyRound, X,
} from "lucide-react";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "Sentinel — Assistente AI di protezione" },
      { name: "description", content: "Barra laterale AI sempre attiva che analizza link, email e file sospetti e ti protegge in tempo reale." },
      { property: "og:title", content: "Sentinel — Assistente AI di protezione" },
      { property: "og:description", content: "Il tuo assistente di sicurezza sempre attivo, a lato dello schermo." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary" },
    ],
  }),
  component: Index,
});

const STORAGE = "sentinel-chat-v1";

const QUICK = [
  { icon: Link2, label: "Link", prompt: "Analizza questo link: " },
  { icon: Mail, label: "Email", prompt: "Questa email è sicura?\n\n" },
  { icon: KeyRound, label: "Password", prompt: "Valuta la sicurezza di questa password (non è quella vera): " },
];

function beep() {
  try {
    const ctx = new AudioContext();
    const o = ctx.createOscillator();
    const g = ctx.createGain();
    o.frequency.value = 880;
    g.gain.setValueAtTime(0.06, ctx.currentTime);
    g.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + 0.25);
    o.connect(g).connect(ctx.destination);
    o.start();
    o.stop(ctx.currentTime + 0.25);
  } catch {}
}

function Index() {
  const [muted, setMuted] = useState(false);
  const [locked, setLocked] = useState(false);
  const [open, setOpen] = useState(true);
  const [input, setInput] = useState("");
  const [files, setFiles] = useState<FileList | null>(null);
  const [loaded, setLoaded] = useState(false);
  const taRef = useRef<HTMLTextAreaElement>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  const endRef = useRef<HTMLDivElement>(null);
  const mutedRef = useRef(muted);
  mutedRef.current = muted;

  const { messages, sendMessage, status, stop, setMessages, error } = useChat({
    transport: new DefaultChatTransport({ api: "/api/chat" }),
    onFinish: ({ message }) => {
      if (mutedRef.current) return;
      beep();
      const text = message.parts.map((p) => (p.type === "text" ? p.text : "")).join("");
      if (/🔴|PERICOLO/.test(text) && "Notification" in window && Notification.permission === "granted") {
        const n = new Notification("Sentinel · Minaccia rilevata", {
          body: text.replace(/🔴\s*PERICOLO\s*/, "").slice(0, 160),
          icon: "/icon-192.png",
          requireInteraction: true,
        });
        n.onclick = () => { window.focus(); n.close(); };
      }
    },
  });

  useEffect(() => {
    try {
      const raw = localStorage.getItem(STORAGE);
      if (raw) setMessages(JSON.parse(raw) as UIMessage[]);
    } catch {}
    setLoaded(true);
  }, [setMessages]);

  useEffect(() => {
    if (loaded && status === "ready") localStorage.setItem(STORAGE, JSON.stringify(messages));
  }, [messages, status, loaded]);

  useEffect(() => { endRef.current?.scrollIntoView({ behavior: "smooth" }); }, [messages, status]);
  useEffect(() => { if (!locked && open && status === "ready") taRef.current?.focus(); }, [locked, open, status]);

  const busy = status === "submitted" || status === "streaming";

  const [pip, setPip] = useState<Window | null>(null);
  const [canPip, setCanPip] = useState(false);
  useEffect(() => setCanPip("documentPictureInPicture" in window), []);
  const togglePip = async () => {
    if (pip) { pip.close(); return; }
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const w: Window = await (window as any).documentPictureInPicture.requestWindow({ width: 380, height: 720 });
    document.querySelectorAll('link[rel="stylesheet"], style').forEach((el) => w.document.head.appendChild(el.cloneNode(true)));
    w.document.body.style.margin = "0";
    w.document.body.style.height = "100vh";
    w.addEventListener("pagehide", () => setPip(null));
    setPip(w);
  };

  const submit = () => {
    if ("Notification" in window && Notification.permission === "default") void Notification.requestPermission();
    if (locked || busy || (!input.trim() && !files?.length)) return;
    const text = input.trim() || "Analizza questo file.";
    sendMessage(files?.length ? { text, files } : { text });
    setInput("");
    setFiles(null);
    if (fileRef.current) fileRef.current.value = "";
  };

  const state = locked ? "paused" : muted ? "silent" : "active";
  const stateLabel = { active: "Protezione attiva", silent: "Attiva · silenziata", paused: "In pausa" }[state];

  return (
    <div className="flex h-screen w-full overflow-hidden desk-grid">
      {/* Desktop area — the user's normal work happens here */}
      <div className="hidden flex-1 items-end p-8 md:flex">
        <p className="font-mono text-xs text-muted-foreground/50">
          Sentinel lavora in background · lato destro
        </p>
      </div>

      {!open ? (
        <button
          onClick={() => setOpen(true)}
          className="ml-auto flex h-full w-14 flex-col items-center gap-4 border-l bg-background py-5 text-muted-foreground transition hover:text-foreground"
          aria-label="Apri Sentinel"
        >
          <StatusDot state={state} />
          <PanelRightOpen className="h-4 w-4" />
        </button>
      ) : (
        <PipHost win={pip}>
        <aside className="relative ml-auto flex h-full w-full flex-col border-l bg-background md:w-[20vw] md:min-w-[340px] md:max-w-[420px]">
          {/* Header */}
          <header className="flex items-center gap-3 border-b px-4 py-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary/10 text-primary">
              <ShieldCheck className="h-5 w-5" />
            </div>
            <div className="min-w-0 flex-1">
              <div className="text-sm font-semibold tracking-tight">Sentinel</div>
              <div className="flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
                <StatusDot state={state} small /> {stateLabel}
              </div>
            </div>
            <IconBtn label={muted ? "Riattiva suoni" : "Silenzia"} active={muted} onClick={() => setMuted((m) => !m)}>
              {muted ? <BellOff className="h-4 w-4" /> : <Bell className="h-4 w-4" />}
            </IconBtn>
            <IconBtn label={locked ? "Sblocca" : "Blocca"} active={locked} onClick={() => setLocked((l) => !l)}>
              {locked ? <Lock className="h-4 w-4" /> : <Unlock className="h-4 w-4" />}
            </IconBtn>
            {canPip && (
              <IconBtn label={pip ? "Riporta nella pagina" : "Sempre in primo piano"} active={!!pip} onClick={togglePip}>
                {pip ? <PinOff className="h-4 w-4" /> : <Pin className="h-4 w-4" />}
              </IconBtn>
            )}
            <IconBtn label="Riduci" onClick={() => setOpen(false)}>
              <PanelRightClose className="h-4 w-4" />
            </IconBtn>
          </header>

          {/* Messages */}
          <div className="flex-1 space-y-4 overflow-y-auto px-4 py-4">
            {messages.length === 0 && (
              <div className="mt-6 space-y-3 text-sm text-muted-foreground">
                <p className="text-foreground">Ciao, sono qui a proteggerti.</p>
                <p>Incollami un link, un'email o allega un file o uno screenshot sospetto: ti dico subito se è sicuro.</p>
              </div>
            )}
            {messages.map((m) => (
              <div key={m.id} className={m.role === "user" ? "flex justify-end" : ""}>
                <div
                  className={
                    m.role === "user"
                      ? "max-w-[85%] rounded-2xl rounded-br-sm bg-primary px-3.5 py-2 text-sm text-primary-foreground"
                      : "text-sm leading-relaxed text-foreground"
                  }
                >
                  {m.parts.map((p, i) =>
                    p.type === "text" ? (
                      <div key={i} className="whitespace-pre-wrap break-words">{p.text}</div>
                    ) : p.type === "file" ? (
                      <div key={i} className="mt-1 font-mono text-[11px] opacity-80">📎 {p.filename ?? p.mediaType}</div>
                    ) : null,
                  )}
                </div>
              </div>
            ))}
            {status === "submitted" && (
              <div className="flex gap-1 py-1">
                {[0, 1, 2].map((i) => (
                  <span key={i} className="h-1.5 w-1.5 animate-bounce rounded-full bg-primary" style={{ animationDelay: `${i * 120}ms` }} />
                ))}
              </div>
            )}
            {error && (
              <div className="rounded-lg border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive">
                Analisi non riuscita. Riprova tra poco.
              </div>
            )}
            <div ref={endRef} />
          </div>

          {/* Quick actions */}
          <div className="flex gap-1.5 px-4 pb-2">
            {QUICK.map((q) => (
              <button
                key={q.label}
                disabled={locked}
                onClick={() => { setInput(q.prompt); taRef.current?.focus(); }}
                className="flex items-center gap-1.5 rounded-full border bg-secondary px-2.5 py-1 text-[11px] text-secondary-foreground transition hover:border-primary/50 hover:text-primary disabled:opacity-40"
              >
                <q.icon className="h-3 w-3" /> {q.label}
              </button>
            ))}
            {messages.length > 0 && (
              <button
                onClick={() => { setMessages([]); localStorage.removeItem(STORAGE); }}
                className="ml-auto rounded-full p-1.5 text-muted-foreground transition hover:text-destructive"
                aria-label="Cancella conversazione"
              >
                <Trash2 className="h-3.5 w-3.5" />
              </button>
            )}
          </div>

          {/* Composer */}
          <div className="border-t p-3">
            {files?.length ? (
              <div className="mb-2 flex items-center gap-2 rounded-md bg-secondary px-2 py-1 font-mono text-[11px]">
                <Paperclip className="h-3 w-3" />
                <span className="flex-1 truncate">{Array.from(files).map((f) => f.name).join(", ")}</span>
                <button onClick={() => { setFiles(null); if (fileRef.current) fileRef.current.value = ""; }}><X className="h-3 w-3" /></button>
              </div>
            ) : null}
            <div className="flex items-end gap-2 rounded-xl border bg-card p-2 focus-within:border-primary/50">
              <input ref={fileRef} type="file" multiple hidden accept="image/*,.pdf,.txt,.eml,.html,.js,.json,.csv" onChange={(e) => setFiles(e.target.files)} />
              <button disabled={locked} onClick={() => fileRef.current?.click()} className="p-1.5 text-muted-foreground transition hover:text-foreground disabled:opacity-40" aria-label="Allega file">
                <Paperclip className="h-4 w-4" />
              </button>
              <textarea
                ref={taRef}
                rows={1}
                value={input}
                disabled={locked}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); submit(); } }}
                placeholder="Chiedi o incolla qualcosa…"
                className="max-h-32 min-h-[28px] flex-1 resize-none bg-transparent py-1 text-sm outline-none placeholder:text-muted-foreground disabled:opacity-40"
              />
              {busy ? (
                <button onClick={() => stop()} className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-secondary text-foreground" aria-label="Ferma">
                  <Square className="h-3.5 w-3.5" />
                </button>
              ) : (
                <button onClick={submit} disabled={locked || (!input.trim() && !files?.length)} className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-primary text-primary-foreground transition disabled:opacity-30" aria-label="Invia">
                  <ArrowUp className="h-4 w-4" />
                </button>
              )}
            </div>
          </div>

          {locked && (
            <div className="absolute inset-x-0 bottom-0 top-[61px] flex flex-col items-center justify-center gap-4 bg-background/85 backdrop-blur-sm">
              <Lock className="h-8 w-8 text-muted-foreground" />
              <p className="text-sm text-muted-foreground">Sentinel è in pausa</p>
              <button onClick={() => setLocked(false)} className="rounded-full bg-primary px-4 py-1.5 text-sm font-medium text-primary-foreground glow-primary">
                Riattiva
              </button>
            </div>
          )}
        </aside>
        </PipHost>
      )}
    </div>
  );
}

function StatusDot({ state, small }: { state: "active" | "silent" | "paused"; small?: boolean }) {
  const color = state === "active" ? "bg-primary" : state === "silent" ? "bg-warning" : "bg-muted-foreground";
  const size = small ? "h-1.5 w-1.5" : "h-2.5 w-2.5";
  return (
    <span className={`relative inline-flex ${size}`}>
      {state === "active" && <span className={`absolute inset-0 rounded-full ${color} animate-pulse-ring`} />}
      <span className={`relative inline-flex ${size} rounded-full ${color}`} />
    </span>
  );
}

function IconBtn({ children, label, onClick, active }: { children: React.ReactNode; label: string; onClick: () => void; active?: boolean }) {
  return (
    <button
      onClick={onClick}
      title={label}
      aria-label={label}
      className={`rounded-md p-1.5 transition ${active ? "bg-accent text-warning" : "text-muted-foreground hover:bg-accent hover:text-foreground"}`}
    >
      {children}
    </button>
  );
}

function PipHost({ win, children }: { win: Window | null; children: ReactNode }) {
  if (!win) return <>{children}</>;
  return (
    <>
      <div className="ml-auto flex h-full w-14 items-start justify-center border-l bg-background py-5">
        <StatusDot state="active" />
      </div>
      {createPortal(children, win.document.body)}
    </>
  );
}
