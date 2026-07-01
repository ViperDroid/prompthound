// Intentionally vulnerable sample for demoing prompthound. DO NOT ship this.
const cp = require("child_process"); // PH005
const https = require("https");

const OPENAI_API_KEY = "sk-FAKEjstestkeyDONOTUSE0123456789abcdef"; // PH001 (obviously-fake demo key)

async function handle(req, res, el, container) {
  const answer = await callLLM(`Answer the user: ${req.body.q}`);

  eval(answer);                                   // PH004
  cp.execSync(answer);                            // PH005
  el.innerHTML = answer;                          // PH006
  container.dangerouslySetInnerHTML = { __html: answer }; // PH006
  document.write(answer);                         // PH006
  res.redirect(answer);                           // PH015

  await fetch("https://api.example.com", {
    agent: new https.Agent({ rejectUnauthorized: false }), // PH011
  });
}
