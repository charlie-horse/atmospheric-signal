// Loads the repo's is.neuros.atsignal.* lexicons so every record and
// plaintext payload in the demo is validated against the real schemas.
import { Lexicons } from '@atproto/lexicon'
import { readdirSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { join, dirname } from 'node:path'

const dir = join(dirname(fileURLToPath(import.meta.url)), '../../lexicons/is/neuros/atsignal')

export const lex = new Lexicons()
for (const f of readdirSync(dir)) lex.add(JSON.parse(readFileSync(join(dir, f), 'utf8')))

export const NS = 'is.neuros.atsignal'
