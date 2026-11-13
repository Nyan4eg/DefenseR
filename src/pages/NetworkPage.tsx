import { useMemo, useState } from "react";
import { ArrowUpRight, BadgeCheck, ChevronDown, DoorOpen, Globe, Network, Router, ShieldQuestion, Unplug } from "lucide-react";
import { Avatar, Chip, EmptyState, friendlyName, Rise, StatTile } from "../components/kit";
import { NetConfigCard } from "../components/NetConfigCard";
import { ProcessActions } from "../components/ProcessActions";
import { Card, Loading, PageHeader } from "../components/ui";
import type { Connection, NetConfig, ProcessInfo } from "../lib/api";
import { tr } from "../lib/i18n";

type Filter = "internet" | "listening" | "all";

/** What a port is normally used for, in words a non-specialist knows. */
const PORTS: Record<number, string> = {
  20: "FTP",
  21: "FTP",
  22: "SSH",
  25: tr("почта", "mail"),
  53: "DNS",
  80: tr("сайты (HTTP)", "web (HTTP)"),
  110: tr("почта", "mail"),
  123: tr("время", "time"),
  135: tr("службы Windows", "Windows services"),
  139: tr("общие папки", "file sharing"),
  143: tr("почта", "mail"),
  443: tr("сайты (HTTPS)", "web (HTTPS)"),
  445: tr("общие папки", "file sharing"),
  587: tr("почта", "mail"),
  993: tr("почта", "mail"),
  1900: tr("поиск устройств", "device discovery"),
  3389: tr("удалённый рабочий стол", "remote desktop"),
  5353: tr("поиск устройств", "device discovery"),
};

const STATES: Record<string, string> = {
  ESTABLISHED: tr("установлено", "established"),
  LISTEN: tr("ждёт подключений", "waiting for connections"),
  CLOSE_WAIT: tr("закрывается", "closing"),
  TIME_WAIT: tr("закрывается", "closing"),
  SYN_SENT: tr("подключается", "connecting"),
};

function isListening(connection: Connection): boolean {
  return connection.state === "LISTEN" || connection.protocol === "UDP";
}

/** Listening on an address other computers can reach, not only this one. */
function isOpenToOthers(connection: Connection): boolean {
  // Only TCP: nearly every program keeps a UDP socket for finding devices, which says little.
  return connection.state === "LISTEN" && !connection.localAddr.startsWith("127.") && connection.localAddr !== "::1";
}

function endpoint(address: string, port: number): string {
  return address.includes(":") ? `[${address}]:${port}` : `${address}:${port}`;
}

/** Everything one program is doing on the network, shown as one row. */
interface Group {
  key: string;
  owner: ProcessInfo | null;
  name: string;
  internet: Connection[];
  local: Connection[];
  listening: Connection[];
}

function groupByProgram(connections: Connection[], owners: Map<number, ProcessInfo>): Group[] {
  const groups = new Map<string, Group>();
  for (const connection of connections) {
    const owner = connection.pid != null ? (owners.get(connection.pid) ?? null) : null;
    const key = owner ? (owner.exe ?? `${owner.name}#${owner.pid}`).toLowerCase() : "?";
    let group = groups.get(key);
    if (!group) {
      group = { key, owner, name: owner?.name ?? tr("Неизвестный процесс", "Unknown process"), internet: [], local: [], listening: [] };
      groups.set(key, group);
    }
    if (isListening(connection)) group.listening.push(connection);
    else if (connection.remoteIsPublic) group.internet.push(connection);
    else group.local.push(connection);
  }
  return [...groups.values()];
}

function ConnectionLine({ connection }: { connection: Connection }) {
  const listening = isListening(connection);
  const port = listening ? connection.localPort : (connection.remotePort ?? 0);
  const address = listening
    ? endpoint(connection.localAddr, connection.localPort)
    : connection.remoteAddr && connection.remotePort
      ? endpoint(connection.remoteAddr, connection.remotePort)
      : "—";
  const Icon = listening ? DoorOpen : connection.remoteIsPublic ? Globe : Router;
  return (
    <div className="flex items-center gap-3 rounded-lg bg-white/[0.03] px-3 py-1.5 text-xs">
      <Icon size={13} className={listening ? "text-amber-300" : connection.remoteIsPublic ? "text-cyan-300" : "text-white/40"} />
      <span className="w-52 shrink-0 select-text truncate font-mono tabular-nums text-white/80">{address}</span>
      <span className="w-10 shrink-0 text-white/40">{connection.protocol}</span>
      <span className="min-w-0 flex-1 truncate text-white/55">{PORTS[port] ?? ""}</span>
      <span className="shrink-0 text-white/40">{connection.state ? (STATES[connection.state] ?? connection.state.toLowerCase()) : listening ? STATES.LISTEN : ""}</span>
    </div>
  );
}

function ProgramRow({ group, open, onToggle, onChanged }: { group: Group; open: boolean; onToggle: () => void; onChanged: () => void }) {
  const { owner } = group;
  const title = owner ? friendlyName(owner.name) : group.name;
  const openToOthers = group.listening.filter(isOpenToOthers);
  const destinations = new Set(group.internet.map((connection) => connection.remoteAddr)).size;
  const lines = [...group.internet, ...group.listening, ...group.local];

  return (
    <div className={`rounded-xl transition-colors ${open ? "bg-white/[0.05]" : "hover:bg-white/[0.035]"}`}>
      <button onClick={onToggle} className="flex w-full items-center gap-3 px-3 py-2.5 text-left">
        <Avatar name={group.name} muted={!owner} path={owner?.exe} />
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="truncate text-sm font-medium">{title}</span>
            {owner && title !== owner.name && <span className="truncate text-xs text-white/35">{owner.name}</span>}
          </div>
          <div className="mt-1 flex min-w-0 flex-wrap items-center gap-1.5">
            {owner?.signed === true && (
              <Chip icon={BadgeCheck} tone="accent">
                {owner.publisher ?? tr("Подписан", "Signed")}
              </Chip>
            )}
            {owner?.signed === false && (
              <Chip icon={ShieldQuestion} tone="warn">
                {tr("Без подписи", "Unsigned")}
              </Chip>
            )}
            {openToOthers.length > 0 && (
              <Chip
                icon={DoorOpen}
                tone="warn"
                title={tr("Программа принимает подключения с других компьютеров сети", "The program accepts connections from other computers on the network")}
              >
                {tr(`Принимает подключения: порт ${openToOthers[0].localPort}`, `Accepts connections: port ${openToOthers[0].localPort}`)}
                {openToOthers.length > 1 ? ` +${openToOthers.length - 1}` : ""}
              </Chip>
            )}
          </div>
        </div>

        <div className="w-28 shrink-0 text-right">
          <div className={`text-sm font-medium tabular-nums ${group.internet.length > 0 ? "text-cyan-300" : "text-white/35"}`}>{group.internet.length}</div>
          <div className="text-xs text-white/35">{tr("в интернет", "to the internet")}</div>
        </div>
        <div className="w-24 shrink-0 text-right">
          <div className="text-sm font-medium tabular-nums text-white/75">{destinations}</div>
          <div className="text-xs text-white/35">{tr("адресов", "addresses")}</div>
        </div>
        <ChevronDown size={16} className={`shrink-0 text-white/30 transition-transform duration-200 ${open ? "rotate-180" : ""}`} />
      </button>

      {open && (
        <div className="rise mx-3 mb-3 flex flex-col gap-3 rounded-xl border border-white/8 bg-black/20 px-4 py-3">
          {owner ? (
            <ProcessActions pid={owner.pid} path={owner.exe} name={owner.name} onDone={onChanged} />
          ) : (
            <div className="text-xs text-white/45">
              {tr("Windows не сообщила, какому процессу принадлежат эти соединения.", "Windows did not say which process these connections belong to.")}
            </div>
          )}
          <div>
            <div className="mb-1.5 text-xs text-white/40">{tr(`Соединения: ${lines.length}`, `Connections: ${lines.length}`)}</div>
            <div className="flex flex-col gap-1">
              {lines.slice(0, 15).map((connection, index) => (
                <ConnectionLine key={index} connection={connection} />
              ))}
              {lines.length > 15 && <div className="px-3 py-1 text-xs text-white/35">{tr(`…и ещё ${lines.length - 15}`, `…and ${lines.length - 15} more`)}</div>}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

interface Props {
  connections: Connection[] | null;
  processes: ProcessInfo[] | null;
  netConfig: NetConfig | null;
  /** Called after a response action, so lists elsewhere refresh. */
  onChanged: () => void;
}

export function NetworkPage({ connections, processes, netConfig, onChanged }: Props) {
  const [filter, setFilter] = useState<Filter>("internet");
  /** The program whose row is expanded. */
  const [open, setOpen] = useState<string | null>(null);

  const owners = useMemo(() => new Map((processes ?? []).map((process) => [process.pid, process])), [processes]);
  const groups = useMemo(() => groupByProgram(connections ?? [], owners), [connections, owners]);

  const online = groups.filter((group) => group.internet.length > 0);
  const accepting = groups.filter((group) => group.listening.some(isOpenToOthers));
  const internetConnections = connections?.filter((connection) => connection.remoteIsPublic && !isListening(connection)).length ?? 0;

  const rows = (filter === "internet" ? online : filter === "listening" ? accepting : groups).sort(
    (a, b) => b.internet.length - a.internet.length || b.listening.length - a.listening.length || a.name.localeCompare(b.name),
  );

  return (
    <div className="flex h-full flex-col">
      <PageHeader
        title={tr("Сеть", "Network")}
        subtitle={tr("Какие программы сейчас общаются по сети и с кем. Нажмите на программу, чтобы увидеть адреса и действия", "Which programs are talking over the network right now, and to whom. Click a program for addresses and actions")}
      />

      <div className="mb-4 flex gap-3">
        <StatTile
          icon={Globe}
          label={tr("Программ в интернете", "Programs online")}
          value={online.length}
          tone="info"
          hint={tr(`соединений: ${internetConnections}`, `connections: ${internetConnections}`)}
          onClick={() => setFilter("internet")}
          active={filter === "internet"}
        />
        <StatTile
          icon={DoorOpen}
          label={tr("Принимают подключения", "Accept connections")}
          value={accepting.length}
          tone="warn"
          hint={tr("доступны другим компьютерам сети", "reachable from other computers")}
          onClick={() => setFilter("listening")}
          active={filter === "listening"}
        />
        <StatTile
          icon={Network}
          label={tr("Всего программ в сети", "All programs on the network")}
          value={groups.length}
          hint={tr(`сокетов: ${connections?.length ?? 0}`, `sockets: ${connections?.length ?? 0}`)}
          onClick={() => setFilter("all")}
          active={filter === "all"}
        />
      </div>

      <NetConfigCard config={netConfig} />

      <div className="mb-3 flex items-center gap-4 px-1 text-xs text-white/40">
        <span className="flex items-center gap-1.5">
          <Globe size={12} className="text-cyan-300" />
          {tr("адрес в интернете", "internet address")}
        </span>
        <span className="flex items-center gap-1.5">
          <Router size={12} />
          {tr("домашняя сеть или этот компьютер", "home network or this computer")}
        </span>
        <span className="flex items-center gap-1.5">
          <DoorOpen size={12} className="text-amber-300" />
          {tr("открытый порт", "open port")}
        </span>
        <span className="flex-1" />
        <span className="flex items-center gap-1">
          <ArrowUpRight size={12} />
          {tr("обновляется каждые 5 секунд", "refreshes every 5 seconds")}
        </span>
      </div>

      <Card className="min-h-0 flex-1 overflow-auto p-2">
        {!connections ? (
          <Loading />
        ) : rows.length === 0 ? (
          <EmptyState
            icon={Unplug}
            title={filter === "listening" ? tr("Никто не принимает подключения", "Nothing accepts connections") : tr("Соединений нет", "No connections")}
            text={
              filter === "listening"
                ? tr("Ни одна программа не открыта для других компьютеров сети — это хорошо.", "No program is open to other computers on the network — that is good.")
                : tr("Сейчас ни одна программа не общается по сети.", "No program is using the network right now.")
            }
          />
        ) : (
          rows.map((group, index) => (
            <Rise key={group.key} index={index}>
              <ProgramRow group={group} open={open === group.key} onToggle={() => setOpen(open === group.key ? null : group.key)} onChanged={onChanged} />
            </Rise>
          ))
        )}
      </Card>
    </div>
  );
}
