import { useMemo, useState } from "react";
import { BadgeCheck, Check, ChevronDown, Code, Copy, Eye, Globe, PackagePlus, PowerOff, Puzzle, ShieldQuestion, Sparkles, TriangleAlert } from "lucide-react";
import { Avatar, Chip, EmptyState, Rise, StatTile } from "../components/kit";
import { Card, Loading, PageHeader, SearchInput, Tabs } from "../components/ui";
import { formatTime, type BrowserExtension } from "../lib/api";
import { tr } from "../lib/i18n";

type Filter = "all" | "all-sites" | "outside" | "off";

/** What each sensitive permission lets an extension do, in plain words. */
const PERMISSIONS: Record<string, string> = {
  nativeMessaging: tr("Общается с программами, установленными на компьютере", "Talks to programs installed on the computer"),
  debugger: tr("Может управлять вкладками как отладчик — это полный доступ к страницам", "Can drive tabs as a debugger — that is full access to pages"),
  proxy: tr("Управляет прокси: может направить весь трафик браузера через свой сервер", "Controls the proxy: it can send all browser traffic through its own server"),
  webRequest: tr("Видит сетевые запросы браузера", "Sees the browser's network requests"),
  cookies: tr("Читает cookie сайтов — в том числе тех, где вы вошли в аккаунт", "Reads site cookies — including sites you are signed in to"),
  history: tr("Читает историю посещений", "Reads the browsing history"),
  tabs: tr("Видит адреса и заголовки открытых вкладок", "Sees the addresses and titles of open tabs"),
  clipboardRead: tr("Читает буфер обмена", "Reads the clipboard"),
  downloads: tr("Управляет загрузками", "Manages downloads"),
  management: tr("Управляет другими расширениями", "Manages other extensions"),
  privacy: tr("Меняет настройки приватности браузера", "Changes the browser's privacy settings"),
  scripting: tr("Вставляет свой код в страницы", "Injects its own code into pages"),
  desktopCapture: tr("Может записывать экран", "Can capture the screen"),
  browsingData: tr("Может стирать данные браузера", "Can erase browser data"),
};

const SOURCES: Record<BrowserExtension["source"], { label: string; tone: "accent" | "warn" | "danger"; icon: typeof BadgeCheck; text: string }> = {
  store: {
    label: tr("Из магазина", "From the store"),
    tone: "accent",
    icon: BadgeCheck,
    text: tr("Установлено из магазина расширений браузера, где расширения проходят проверку.", "Installed from the browser's extension store, where extensions are reviewed."),
  },
  unpacked: {
    label: tr("Режим разработчика", "Developer mode"),
    tone: "warn",
    icon: Code,
    text: tr("Загружено из папки на компьютере в режиме разработчика. Так делают разработчики; так же расширение может подложить и посторонняя программа.", "Loaded from a folder on the computer in developer mode. Developers do this; another program can plant an extension the same way."),
  },
  external: {
    label: tr("Добавлено извне", "Added from outside"),
    tone: "danger",
    icon: PackagePlus,
    text: tr("Его добавили не вы в браузере, а другая программа или политика компьютера. Так ставят расширения антивирусы и корпоративные настройки, но и рекламные программы тоже.", "It was added not by you in the browser, but by another program or a computer policy. Antivirus products and company settings install extensions this way, but so does adware."),
  },
  other: {
    label: tr("Не из магазина", "Not from the store"),
    tone: "warn",
    icon: ShieldQuestion,
    text: tr("Расширение получает обновления не из магазина браузера, поэтому его никто не проверял.", "The extension is not updated from the browser's store, so no one has reviewed it."),
  },
};

function rank(extension: BrowserExtension): number {
  return (extension.source === "store" ? 0 : 4) + (extension.allSites ? 2 : 0) + (extension.enabled ? 1 : 0);
}

function ExtensionRow({ extension, open, onToggle }: { extension: BrowserExtension; open: boolean; onToggle: () => void }) {
  const [copied, setCopied] = useState(false);
  const source = SOURCES[extension.source];

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(extension.manageUrl);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // The address stays on screen and can be selected by hand.
    }
  };

  return (
    <div className={`rounded-xl transition-colors ${open ? "bg-white/[0.05]" : "hover:bg-white/[0.035]"} ${extension.enabled ? "" : "opacity-60 hover:opacity-100"}`}>
      <button onClick={onToggle} className="flex w-full items-center gap-3 px-3 py-2.5 text-left">
        <Avatar name={extension.name} muted={!extension.enabled} />
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="truncate text-sm font-medium">{extension.name}</span>
            <span className="shrink-0 text-xs text-white/35">{extension.version}</span>
          </div>
          <div className="mt-1 flex min-w-0 flex-wrap items-center gap-1.5">
            <Chip icon={Globe}>
              {extension.browser}
              {extension.profile !== "Default" && !extension.profile.includes(".") ? ` · ${extension.profile}` : ""}
            </Chip>
            <Chip icon={source.icon} tone={source.tone}>
              {source.label}
            </Chip>
            {extension.allSites && (
              <Chip icon={Eye} tone="warn" title={tr("Может читать и менять страницы любого сайта", "Can read and change the pages of any site")}>
                {tr("Видит все сайты", "Sees every site")}
              </Chip>
            )}
            {extension.permissions.length > 0 && <Chip icon={Sparkles}>{tr(`Особых разрешений: ${extension.permissions.length}`, `Special permissions: ${extension.permissions.length}`)}</Chip>}
            {!extension.enabled && <Chip icon={PowerOff}>{tr("Выключено в браузере", "Turned off in the browser")}</Chip>}
          </div>
        </div>
        <ChevronDown size={16} className={`shrink-0 text-white/30 transition-transform duration-200 ${open ? "rotate-180" : ""}`} />
      </button>

      {open && (
        <div className="rise mx-3 mb-3 flex flex-col gap-3 rounded-xl border border-white/8 bg-black/20 px-4 py-3 text-xs">
          <div>
            <div className="mb-1 text-white/40">{tr("Откуда", "Where it came from")}</div>
            <div className="leading-relaxed text-white/70">
              {source.text}
              {extension.installedAt ? tr(` Установлено ${formatTime(extension.installedAt)}.`, ` Installed ${formatTime(extension.installedAt)}.`) : ""}
            </div>
          </div>

          <div>
            <div className="mb-1 text-white/40">{tr("Что ему разрешено", "What it is allowed to do")}</div>
            <ul className="flex flex-col gap-1 leading-relaxed text-white/70">
              <li className="flex gap-2">
                <Eye size={13} className={`mt-0.5 shrink-0 ${extension.allSites ? "text-amber-300" : "text-white/35"}`} />
                {extension.allSites
                  ? tr("Читать и менять страницы всех сайтов, которые вы открываете", "Read and change the pages of every site you open")
                  : tr("Работать только на отдельных сайтах или по вашему нажатию", "Work only on particular sites or when you click it")}
              </li>
              {extension.permissions.map((name) => (
                <li key={name} className="flex gap-2">
                  <Sparkles size={13} className="mt-0.5 shrink-0 text-white/35" />
                  <span>
                    {PERMISSIONS[name] ?? name} <span className="font-mono text-white/30">{name}</span>
                  </span>
                </li>
              ))}
            </ul>
          </div>

          <div>
            <div className="mb-1 text-white/40">{tr("Как выключить или удалить", "How to turn it off or remove it")}</div>
            <div className="leading-relaxed text-white/70">
              {tr(
                "Браузеры не дают посторонним программам удалять расширения, поэтому это делается в самом браузере. Скопируйте адрес и вставьте его в адресную строку:",
                "Browsers do not let outside programs remove extensions, so this is done in the browser itself. Copy the address and paste it into the address bar:",
              )}
            </div>
            <div className="mt-1.5 flex items-center gap-2">
              <code className="min-w-0 flex-1 select-text truncate rounded-lg bg-white/[0.05] px-2.5 py-1.5 font-mono text-white/80">{extension.manageUrl}</code>
              <button onClick={copy} className="flex shrink-0 items-center gap-1.5 rounded-lg bg-white/8 px-2.5 py-1.5 text-white/70 hover:bg-white/12">
                {copied ? <Check size={13} className="text-emerald-300" /> : <Copy size={13} />}
                {copied ? tr("Скопировано", "Copied") : tr("Копировать", "Copy")}
              </button>
            </div>
          </div>

          <div className="select-text font-mono text-white/30">{extension.id}</div>
        </div>
      )}
    </div>
  );
}

export function ExtensionsPage({ extensions }: { extensions: BrowserExtension[] | null }) {
  const [filter, setFilter] = useState<Filter>("all");
  const [browser, setBrowser] = useState("all");
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState<string | null>(null);

  const all = extensions ?? [];
  const browsers = useMemo(() => [...new Set(all.map((extension) => extension.browser))].sort(), [all]);
  const inBrowser = all.filter((extension) => browser === "all" || extension.browser === browser);

  const allSites = inBrowser.filter((extension) => extension.enabled && extension.allSites).length;
  const outside = inBrowser.filter((extension) => extension.source !== "store").length;
  const off = inBrowser.filter((extension) => !extension.enabled).length;

  const rows = inBrowser
    .filter((extension) => filter === "all" || (filter === "all-sites" ? extension.enabled && extension.allSites : filter === "outside" ? extension.source !== "store" : !extension.enabled))
    .filter((extension) => {
      const q = query.trim().toLowerCase();
      return !q || extension.name.toLowerCase().includes(q) || extension.id.toLowerCase().includes(q);
    })
    .sort((a, b) => rank(b) - rank(a) || a.name.localeCompare(b.name));
  const toggle = (next: Filter) => setFilter(filter === next ? "all" : next);

  return (
    <div className="flex h-full flex-col">
      <PageHeader
        title={tr("Расширения браузеров", "Browser extensions")}
        subtitle={tr(
          "Расширение видит страницы, которые вы открываете. Здесь — что установлено, откуда оно взялось и что ему разрешено",
          "An extension sees the pages you open. Here is what is installed, where it came from and what it is allowed to do",
        )}
      />

      <div className="mb-4 flex gap-3">
        <StatTile icon={Puzzle} label={tr("Всего расширений", "All extensions")} value={inBrowser.length} onClick={() => setFilter("all")} active={filter === "all"} />
        <StatTile
          icon={Eye}
          label={tr("Видят все сайты", "See every site")}
          value={allSites}
          tone={allSites > 0 ? "warn" : "neutral"}
          hint={tr("читают и меняют любые страницы", "read and change any page")}
          onClick={() => toggle("all-sites")}
          active={filter === "all-sites"}
        />
        <StatTile
          icon={TriangleAlert}
          label={tr("Не из магазина", "Not from the store")}
          value={outside}
          tone={outside > 0 ? "danger" : "accent"}
          hint={outside > 0 ? tr("их никто не проверял", "no one has reviewed them") : tr("все из магазинов", "all from stores")}
          onClick={() => toggle("outside")}
          active={filter === "outside"}
        />
        <StatTile icon={PowerOff} label={tr("Выключены", "Turned off")} value={off} hint={tr("установлены, но не работают", "installed, but not running")} onClick={() => toggle("off")} active={filter === "off"} />
      </div>

      <div className="mb-3 flex items-center gap-3">
        <SearchInput value={query} onChange={setQuery} placeholder={tr("Название расширения", "Extension name")} />
        {browsers.length > 1 && (
          <Tabs
            value={browser}
            onChange={setBrowser}
            options={[
              { id: "all", label: tr(`Все · ${all.length}`, `All · ${all.length}`) },
              ...browsers.map((name) => ({ id: name, label: `${name} · ${all.filter((extension) => extension.browser === name).length}` })),
            ]}
          />
        )}
      </div>

      <Card className="min-h-0 flex-1 overflow-auto p-2">
        {!extensions ? (
          <Loading />
        ) : rows.length === 0 ? (
          <EmptyState
            icon={Puzzle}
            tone={filter === "outside" || filter === "all-sites" ? "accent" : "neutral"}
            title={all.length === 0 ? tr("Расширений не найдено", "No extensions found") : tr("Здесь пусто", "Nothing here")}
            text={
              all.length === 0
                ? tr("DefenseR смотрит Chrome, Edge, Opera, Brave, Яндекс Браузер и Firefox.", "DefenseR looks at Chrome, Edge, Opera, Brave, Yandex Browser and Firefox.")
                : filter === "outside"
                  ? tr("Все расширения установлены из магазинов браузеров — это хорошо.", "Every extension was installed from a browser store — that is good.")
                  : tr("Под этот фильтр не попало ни одно расширение.", "No extension matches this filter.")
            }
          />
        ) : (
          rows.map((extension, index) => {
            const key = `${extension.browser}|${extension.profile}|${extension.id}`;
            return (
              <Rise key={key} index={index}>
                <ExtensionRow extension={extension} open={open === key} onToggle={() => setOpen(open === key ? null : key)} />
              </Rise>
            );
          })
        )}
      </Card>
    </div>
  );
}
