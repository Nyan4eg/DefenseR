// Builds a signed installer and publishes it as a GitHub release: npm run release -- "What's new"
// The signing key stays on this machine, in ~/.tauri/defenser.key; only the signature is published.
// `--build-only` stops after the build, without publishing anything.
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const args = process.argv.slice(2);
const buildOnly = args.includes("--build-only");
const notes = args.filter((arg) => !arg.startsWith("--")).join(" ") || "Исправления и улучшения.";

const run = (command, commandArgs) => execFileSync(command, commandArgs, { cwd: root, encoding: "utf8" }).trim();
const fail = (message) => {
  console.error(message);
  process.exit(1);
};

const keyPath = join(homedir(), ".tauri", "defenser.key");
if (!existsSync(keyPath)) fail(`Ключ подписи не найден: ${keyPath}`);

const { version } = JSON.parse(readFileSync(join(root, "src-tauri", "tauri.conf.json"), "utf8"));
const tag = `v${version}`;
if (!buildOnly) {
  if (run("git", ["status", "--porcelain"])) fail("Есть незакоммиченные изменения: сначала закоммитьте их.");
  if (run("git", ["tag", "--list", tag])) fail(`Версия ${version} уже выпущена: поднимите версию.`);
}

const build = spawnSync("npm", ["run", "tauri", "build", "--", "--bundles", "nsis"], {
  cwd: root,
  stdio: "inherit",
  shell: true,
  env: { ...process.env, TAURI_SIGNING_PRIVATE_KEY: readFileSync(keyPath, "utf8"), TAURI_SIGNING_PRIVATE_KEY_PASSWORD: "" },
});
if (build.status !== 0) fail("Сборка не удалась.");

const bundle = join(root, "src-tauri", "target", "release", "bundle", "nsis");
const installer = `DefenseR_${version}_x64-setup.exe`;
const signature = readFileSync(join(bundle, `${installer}.sig`), "utf8");
const repo = buildOnly ? "OWNER/REPO" : run("gh", ["repo", "view", "--json", "nameWithOwner", "--jq", ".nameWithOwner"]);
const platform = { signature, url: `https://github.com/${repo}/releases/download/${tag}/${installer}` };
const manifest = { version, notes, pub_date: new Date().toISOString(), platforms: { "windows-x86_64": platform, "windows-x86_64-nsis": platform } };
const manifestPath = join(bundle, "latest.json");
writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
console.log(`Собрано: ${join(bundle, installer)}`);
if (buildOnly) process.exit(0);

// The network step most likely to fail for a moment: tried a few times, and git's own words are shown.
const sleep = (ms) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
const attempt = (what, command, commandArgs, tries = 3) => {
  for (let turn = 1; ; turn++) {
    const result = spawnSync(command, commandArgs, { cwd: root, encoding: "utf8" });
    if (result.status === 0) return result.stdout.trim();
    console.error(`${what}: попытка ${turn} из ${tries} не удалась.
${(result.stderr || result.stdout || String(result.error ?? "")).trim()}`);
    if (turn === tries) fail(`ВЫПУСК НЕ СОСТОЯЛСЯ: ${what.toLowerCase()} не удалось. Установщик собран, выпуск ${tag} не создан — запустите команду ещё раз.`);
    sleep(turn * 10_000);
  }
};

attempt("Отправка коммитов на GitHub", "git", ["push", "origin", "HEAD"]);
attempt("Создание выпуска", "gh", ["release", "create", tag, join(bundle, installer), manifestPath, "--title", `DefenseR ${version}`, "--notes", notes], 2);

// What installed copies will actually see: the manifest GitHub serves as the latest one.
const served = attempt("Проверка выпуска", "gh", ["release", "view", "--json", "tagName,assets", "--jq", '.tagName + " " + ([.assets[].name] | join(","))']);
if (!served.startsWith(`${tag} `) || !served.includes(installer) || !served.includes("latest.json")) {
  fail(`ВЫПУСК НЕ СОСТОЯЛСЯ: последним на GitHub значится «${served}», а не ${tag} с установщиком и latest.json.`);
}
console.log(`Выпуск ${tag} опубликован: https://github.com/${repo}/releases/tag/${tag}`);
