import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { Lexicons, parseLexiconDoc, type LexiconDoc } from '@atproto/lexicon'

// toy/shared/src -> repo root -> lexicons/is/neuros/atsignal
const LEXICON_DIR = fileURLToPath(new URL('../../../lexicons/is/neuros/atsignal/', import.meta.url))

/** Reads and parses the atsignal lexicon JSON files (7 of them) from the repo. */
export function loadLexiconDocs(): LexiconDoc[] {
  return readdirSync(LEXICON_DIR)
    .filter((f) => f.endsWith('.json'))
    .sort()
    .map((f) => parseLexiconDoc(JSON.parse(readFileSync(join(LEXICON_DIR, f), 'utf8'))))
}

/** An @atproto/lexicon instance with every atsignal lexicon loaded. */
export const lexicons: Lexicons = new Lexicons(loadLexiconDocs())
