import { readdir, readFile, writeFile } from 'node:fs/promises'
import { basename, join, relative, resolve } from 'node:path'

const sourceRoot = resolve(process.argv[2] ?? '../PatternYard-BackendApi')
const outputPath = resolve(process.argv[3] ?? 'contracts/backend-api-routes.json')
const routesRoot = join(sourceRoot, 'api/v1/routes')

async function walk(directory) {
  const entries = await readdir(directory, { withFileTypes: true })
  const nested = await Promise.all(
    entries
      .filter((entry) => !entry.name.startsWith('_'))
      .map((entry) => {
        const path = join(directory, entry.name)
        return entry.isDirectory() ? walk(path) : [path]
      }),
  )
  return nested.flat()
}

const routePattern = /\.(get|post|put|patch|delete)\s*\(\s*['"`]([^'"`]+)/gi
const files = (await walk(routesRoot)).filter((path) => path.endsWith('.js'))
const routes = []

for (const file of files) {
  const source = await readFile(file, 'utf8')
  for (const match of source.matchAll(routePattern)) {
    routes.push({
      method: match[1].toUpperCase(),
      path: match[2],
      source: relative(sourceRoot, file),
      family: relative(routesRoot, file).split('/')[0],
      status: 'unimplemented',
    })
  }
}

routes.sort((a, b) =>
  a.path.localeCompare(b.path) || a.method.localeCompare(b.method),
)

const inventory = {
  generatedFrom: basename(sourceRoot),
  sourceBranch: 'wycats-main',
  routeCount: routes.length,
  statuses: ['unimplemented', 'parity-tested', 'shadowing', 'cut-over', 'retired'],
  routes,
}

await writeFile(outputPath, `${JSON.stringify(inventory, null, 2)}\n`)
console.log(`Inventoried ${routes.length} routes into ${outputPath}`)
