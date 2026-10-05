import { createFileRoute } from "@tanstack/react-router";
import { convertToModelMessages, type UIMessage } from "ai";
import { createResponsesCall } from "@/lib/ai/responses";

const INSTRUCTIONS = `Sei "Sentinel", un assistente di sicurezza informatica personale, sempre attivo, che vive in una barra laterale del PC dell'utente.
Rispondi SEMPRE in italiano, in testo semplice senza markdown (niente asterischi o backtick), in modo breve, chiaro e pratico (massimo ~120 parole salvo richiesta).
Compiti: analizzare link, email, messaggi, file e screenshot sospetti; riconoscere phishing, truffe, malware, estensioni o download rischiosi; dare consigli di protezione concreti (password, 2FA, aggiornamenti, backup, impostazioni Windows/macOS, antivirus di sistema).
Quando analizzi qualcosa inizia con un verdetto su una riga: "🟢 SICURO", "🟡 ATTENZIONE" oppure "🔴 PERICOLO", poi 2-4 punti con motivi e azioni da fare.
Sii onesto: non puoi scansionare il disco né bloccare processi; se serve, indica come farlo con gli strumenti del sistema.`;

export const Route = createFileRoute("/api/chat")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const apiKey = process.env.LOVABLE_API_KEY;
        if (!apiKey) return new Response("AI non configurata", { status: 500 });
        const { messages } = (await request.json()) as { messages: UIMessage[] };
        const modelMessages = await convertToModelMessages(messages);
        return createResponsesCall(
          request,
          { baseURL: "https://ai.gateway.lovable.dev/v1", apiKey, model: "openai/gpt-6-astra" },
          modelMessages,
          INSTRUCTIONS,
        ).response();
      },
    },
  },
});
