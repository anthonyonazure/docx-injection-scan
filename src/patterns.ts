/**
 * Language and obfuscation handling.
 *
 * Design note: the phrase lists below are the WEAKEST layer on purpose. A payload
 * can be written in any language, in any wording, so keyword matching is treated
 * as supporting evidence only. The load-bearing detections live in detect.ts and
 * are language-independent (formatting, visibility, carrier location).
 */

/**
 * Characters that render as nothing.
 *
 * Includes the Unicode Tags block (U+E0000-E007F), which mirrors the entire
 * ASCII range in characters that display as absolutely nothing in every renderer.
 * A complete payload can be written in it and pasted into visible text with no
 * formatting trick at all - currently the cleanest known smuggling channel.
 */
export const INVISIBLE_CHARS = /[​-‏‪-‮⁠-⁤⁦-⁯﻿­᠎\u{E0000}-\u{E007F}]/gu;

/** Four or more stacked variation selectors: steganography, not emoji styling. */
export const VARIATION_SELECTOR_RUN = /[︀-️\u{E0100}-\u{E01EF}]{4,}/u;

/** Decodes a Unicode Tags payload back to ASCII so its content can be matched. */
export function decodeTagChars(text: string): string {
  return [...text]
    .filter((ch) => ch.codePointAt(0)! >= 0xe0020 && ch.codePointAt(0)! <= 0xe007e)
    .map((ch) => String.fromCharCode(ch.codePointAt(0)! - 0xe0000))
    .join("");
}

/**
 * Unicode confusables not handled by NFKC. Cyrillic and Greek letters that are
 * pixel-identical to Latin ones, used to make "ignore" unmatchable by a regex
 * while staying perfectly readable to a model.
 */
const CONFUSABLES: Record<string, string> = {
  // Cyrillic
  "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
  "у": "y", "х": "x", "і": "i", "ѕ": "s", "ј": "j",
  "һ": "h", "ӏ": "l", "ԁ": "d", "ԛ": "q", "в": "b",
  "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M",
  "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T",
  "Х": "X", "І": "I", "Ј": "J", "Ѕ": "S",
  // Greek
  "α": "a", "ε": "e", "ι": "i", "κ": "k", "ν": "v",
  "ο": "o", "ρ": "p", "τ": "t", "υ": "u", "χ": "x",
  "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H",
  "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O",
  "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
  // Armenian / Cherokee lookalikes
  "օ": "o", "Ꭰ": "D", "Ꭺ": "G",
};

const LATIN = /\p{Script=Latin}/u;
const FOLDABLE_SCRIPT = /[\p{Script=Cyrillic}\p{Script=Greek}\p{Script=Armenian}\p{Script=Cherokee}]/u;

function fold(text: string): string {
  return [...text].map((ch) => CONFUSABLES[ch] ?? ch).join("");
}

/**
 * Folds confusables only inside MIXED-SCRIPT words. "іgnore" (Cyrillic i) folds
 * to "ignore"; genuine Russian stays Russian so its own patterns still match.
 * Folding everything would mangle every Cyrillic and Greek document into
 * nonsense, which is exactly the bug this avoids.
 */
function foldMixedScriptWords(text: string): string {
  return text.replace(/\S+/gu, (token) =>
    LATIN.test(token) && FOLDABLE_SCRIPT.test(token) ? fold(token) : token
  );
}

function baseNormalize(s: string): string {
  return s
    .replace(/[̀-ͯ]/g, "")                                   // stripped diacritics
    .replace(/\s+/g, " ")
    // "i g n o r e   a l l" -> "ignore all": collapse runs of 4+ single letters.
    .replace(/(?:\b\p{L}\s){3,}\p{L}\b/gu, (m) => m.replace(/\s/g, ""))
    .toLowerCase()
    .trim();
}

/**
 * Collapses every trick used to make text unmatchable while keeping it readable:
 * compatibility forms (fullwidth, math-bold), invisible separators, confusable
 * scripts, and letter-spacing.
 */
export function normalize(input: string): string {
  const cleaned = input.normalize("NFKC").replace(INVISIBLE_CHARS, "");
  return baseNormalize(foldMixedScriptWords(cleaned));
}

/**
 * Two readings of the same text, because the two evasions pull in opposite
 * directions: a word built entirely from lookalike letters needs aggressive
 * folding, while a real foreign-language payload needs none. Matching against
 * both readings catches either without sacrificing the other.
 */
export function normalizeVariants(input: string): string[] {
  const cleaned = input.normalize("NFKC").replace(INVISIBLE_CHARS, "");
  const tokenAware = baseNormalize(foldMixedScriptWords(cleaned));
  const fullyFolded = baseNormalize(fold(cleaned));
  return tokenAware === fullyFolded ? [tokenAware] : [tokenAware, fullyFolded];
}

export type PhraseHit = { label: string; language: string; excerpt: string };

/**
 * Multilingual anchors. Grouped by intent rather than by language so a payload
 * translated into any of these still trips the same category.
 */
const PHRASES: Array<{ re: RegExp; label: string; language: string }> = [
  // --- override of prior instructions ---
  { re: /\b(ignore|disregard|forget|override)\b[^.]{0,40}\b(previous|prior|above|earlier|all|any)\b[^.]{0,25}\b(instruction|prompt|rule|direction|command)/i, label: "override of prior instructions", language: "en" },
  { re: /\b(ignora|ignore|olvida|omite)\b[^.]{0,40}\b(instrucciones|indicaciones|reglas)\b[^.]{0,25}\b(anteriores|previas|todas)/i, label: "override of prior instructions", language: "es" },
  { re: /\b(ignore[zr]?|oublie[zr]?|ne tiens? pas compte)\b[^.]{0,40}\b(instructions|consignes|regles)\b[^.]{0,25}\b(precedentes|anterieures|toutes)/i, label: "override of prior instructions", language: "fr" },
  { re: /\b(ignoriere|vergiss|missachte)\b[^.]{0,40}\b(vorherigen|bisherigen|alle)\b[^.]{0,25}\b(anweisungen|anleitungen|regeln)/i, label: "override of prior instructions", language: "de" },
  { re: /\b(ignore|esqueca|desconsidere)\b[^.]{0,40}\b(instrucoes|regras)\b[^.]{0,25}\b(anteriores|previas|todas)/i, label: "override of prior instructions", language: "pt" },
  { re: /\b(ignora|dimentica)\b[^.]{0,40}\b(istruzioni|regole)\b[^.]{0,25}\b(precedenti|tutte)/i, label: "override of prior instructions", language: "it" },
  { re: /(игнорируй|забудь|не учитывай)[^.]{0,40}(предыдущие|все|прежние)[^.]{0,25}(инструкции|указания|правила)/i, label: "override of prior instructions", language: "ru" },
  { re: /(忽略|无视|忘记)[^。]{0,20}(之前|以上|所有|先前)[^。]{0,15}(指令|指示|提示|规则)/, label: "override of prior instructions", language: "zh" },
  { re: /(以前|前|これまで)の(指示|命令|プロンプト)[^。]{0,15}(無視|忘れ)/, label: "override of prior instructions", language: "ja" },
  { re: /(이전|모든)\s?(지시|명령|프롬프트)[^.]{0,15}(무시|잊)/, label: "override of prior instructions", language: "ko" },
  { re: /(تجاهل|انس)[^.]{0,40}(التعليمات|الأوامر)[^.]{0,25}(السابقة|كل)/, label: "override of prior instructions", language: "ar" },
  { re: /(onceki|tum)\s+(talimatlari|komutlari)\s+(yoksay|unut|gormezden)/i, label: "override of prior instructions", language: "tr" },
  { re: /(zignoruj|zapomnij o)\s+(poprzednie|wszystkie|wczesniejsze)\s*(instrukcje|polecenia)/i, label: "override of prior instructions", language: "pl" },
  { re: /(negeer|vergeet)\b[^.]{0,30}\b(vorige|alle)\b[^.]{0,20}\b(instructies|opdrachten)/i, label: "override of prior instructions", language: "nl" },

  // --- reference to the model's own control channel (loanwords, near-universal) ---
  { re: /\b(system|developer|initial|original)[\s\-]?(prompt|message|instruction|persona)\b/i, label: "reference to system prompt", language: "any" },
  { re: /(системный|系统|システム|시스템|sistema|systeem|systeem)[\s\-]?(prompt|промпт|提示词|プロンプト|프롬프트)/i, label: "reference to system prompt", language: "any" },
  { re: /<\/?(system|assistant|user|im_start|im_end|\|?im_sep\|?)>/i, label: "chat role delimiter", language: "any" },
  { re: /\[\s*(system|assistant|inst|\/inst)\s*\]/i, label: "chat role delimiter", language: "any" },

  // --- directive aimed at a named assistant (product names survive translation) ---
  { re: /\b(copilot|chatgpt|gpt-?[45]|claude|gemini|grok|llama|mistral|perplexity)\b[^.]{0,40}\b(must|should|shall|will|needs? to|is required|please)\b/i, label: "directive addressed to an AI", language: "any" },
  { re: /\b(you are|act as|behave as|pretend to be|from now on you)\b[^.]{0,50}\b(assistant|agent|ai|model|copilot|bot|system)\b/i, label: "role reassignment", language: "en" },
  { re: /(eres|actua como|comportate como)[^.]{0,50}(asistente|agente|modelo)/i, label: "role reassignment", language: "es" },
  { re: /(tu es|agis comme|comporte-toi comme)[^.]{0,50}(assistant|agent|modele)/i, label: "role reassignment", language: "fr" },
  { re: /(du bist|verhalte dich wie|agiere als)[^.]{0,50}(assistent|agent|modell)/i, label: "role reassignment", language: "de" },
  { re: /(你(现在)?是|扮演)[^。]{0,20}(助手|助理|代理|模型)/, label: "role reassignment", language: "zh" },

  // --- concealment, the strongest single tell ---
  { re: /\b(do not|don'?t|never|avoid)\b[^.]{0,45}\b(tell|reveal|mention|disclose|show|inform|report|display)\b[^.]{0,35}\b(user|human|reader|anyone|them|this)/i, label: "instruction to conceal from the user", language: "en" },
  { re: /\bno\b[^.]{0,30}\b(reveles|menciones|digas|muestres|informes)\b[^.]{0,30}\b(usuario|nadie|humano)/i, label: "instruction to conceal from the user", language: "es" },
  { re: /\bne\b[^.]{0,30}\b(revele[zr]?|mentionne[zr]?|dis|montre[zr]?)\b[^.]{0,30}\b(utilisateur|personne|humain)/i, label: "instruction to conceal from the user", language: "fr" },
  { re: /(nicht|niemals)[^.]{0,35}(erwahne|verrate|zeige|sage)[^.]{0,30}(benutzer|nutzer|niemandem)/i, label: "instruction to conceal from the user", language: "de" },
  { re: /(不要|切勿|请勿)[^。]{0,20}(告诉|透露|提及|显示)[^。]{0,15}(用户|使用者|任何人)/, label: "instruction to conceal from the user", language: "zh" },
  { re: /(не сообщай|не говори|не раскрывай)[^.]{0,35}(пользовател|никому)/i, label: "instruction to conceal from the user", language: "ru" },

  // --- conditional trigger, the hallmark of a dormant payload ---
  { re: /\b(when|if|whenever)\b[^.]{0,20}\b(the )?(user|someone|anyone|they)\b[^.]{0,20}\b(asks?|requests?|mentions?|says?|queries)/i, label: "conditional trigger on a user question", language: "en" },
  { re: /(cuando|si)\s+(el\s+)?usuario\s+(pregunte|pida|mencione)/i, label: "conditional trigger on a user question", language: "es" },
  { re: /(quand|lorsque|si)\s+(l'?)?utilisateur\s+(demande|pose|mentionne)/i, label: "conditional trigger on a user question", language: "fr" },
  { re: /(当|如果)[^。]{0,15}(用户|使用者)[^。]{0,10}(询问|问|提到|要求)/, label: "conditional trigger on a user question", language: "zh" },

  // --- outbound movement of data ---
  { re: /\b(send|post|upload|forward|transmit|exfiltrate|append)\b[^.]{0,45}\b(https?:\/\/|www\.|url|endpoint|webhook|server|api)/i, label: "outbound data instruction", language: "en" },
  { re: /!\[[^\]]{0,40}\]\(\s*https?:\/\/[^)]{0,200}\)/, label: "auto-loading image link (exfiltration channel)", language: "any" },
  { re: /\b(summar|content|data|text|document)\w{0,6}\b[^.]{0,30}\bin the (url|link|query|parameter)\b/i, label: "outbound data instruction", language: "en" },

  // --- tool and agent abuse ---
  { re: /\b(call|invoke|execute|run|use)\b[^.]{0,25}\b(the )?(tool|function|plugin|connector|api|command|shell|powershell)\b/i, label: "tool invocation instruction", language: "any" },
];

/** Accepts raw text; handles normalization and both confusable readings itself. */
export function matchPhrases(text: string): PhraseHit[] {
  const hits: PhraseHit[] = [];
  const seen = new Set<string>();
  for (const variant of normalizeVariants(text)) {
    for (const { re, label, language } of PHRASES) {
      const m = re.exec(variant);
      if (!m) continue;
      const key = `${label}:${language}`;
      if (seen.has(key)) continue;
      seen.add(key);
      hits.push({ label, language, excerpt: m[0].slice(0, 120) });
    }
  }
  return hits;
}

const SCRIPTS: Array<[string, RegExp]> = [
  ["Latin", /\p{Script=Latin}/u],
  ["Cyrillic", /\p{Script=Cyrillic}/u],
  ["Greek", /\p{Script=Greek}/u],
  ["Han", /\p{Script=Han}/u],
  ["Hiragana", /\p{Script=Hiragana}/u],
  ["Katakana", /\p{Script=Katakana}/u],
  ["Hangul", /\p{Script=Hangul}/u],
  ["Arabic", /\p{Script=Arabic}/u],
  ["Hebrew", /\p{Script=Hebrew}/u],
  ["Devanagari", /\p{Script=Devanagari}/u],
  ["Thai", /\p{Script=Thai}/u],
];

/** Which writing systems appear in a chunk of text, ignoring stray characters. */
export function scriptsUsed(text: string): Set<string> {
  const found = new Set<string>();
  for (const [name, re] of SCRIPTS) {
    let count = 0;
    for (const ch of text) if (re.test(ch) && ++count >= 4) break;
    if (count >= 4) found.add(name);
  }
  return found;
}

/** Long unbroken base64-looking runs, used to smuggle an encoded payload. */
export function findEncodedBlobs(text: string): string[] {
  return (text.match(/[A-Za-z0-9+/]{60,}={0,2}/g) ?? []).filter((b) => {
    const classes = [/[a-z]/, /[A-Z]/, /[0-9]/].filter((r) => r.test(b)).length;
    return classes >= 2 && !/\s/.test(b);
  });
}
