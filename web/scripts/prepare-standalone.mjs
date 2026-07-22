import { cp, mkdir, rm, stat } from "node:fs/promises"
import { dirname, join } from "node:path"

const root = process.cwd()
const standaloneRoot = join(root, ".next", "standalone")

async function requireDirectory(path) {
  const metadata = await stat(path)
  if (!metadata.isDirectory()) throw new Error(`Expected a directory at ${path}`)
}

async function replaceDirectory(source, destination) {
  await requireDirectory(source)
  await mkdir(dirname(destination), { recursive: true })
  await rm(destination, { recursive: true, force: true })
  await cp(source, destination, { recursive: true, force: true })
}

await requireDirectory(standaloneRoot)
await replaceDirectory(join(root, "public"), join(standaloneRoot, "public"))
await replaceDirectory(
  join(root, ".next", "static"),
  join(standaloneRoot, ".next", "static"),
)
