// Node strips the types from `.ts` files but, unlike tsc, does not map the
// `./foo.js` specifiers used in src to `./foo.ts`. This retries such imports
// with the `.ts` extension so the tests can run straight from source.
import { registerHooks } from 'node:module'

registerHooks({
  resolve(specifier, context, nextResolve) {
    try {
      return nextResolve(specifier, context)
    } catch (error) {
      if (!specifier.startsWith('.') || !specifier.endsWith('.js')) throw error
      return nextResolve(specifier.replace(/\.js$/, '.ts'), context)
    }
  },
})
