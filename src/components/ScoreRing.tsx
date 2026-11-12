import { motion } from "framer-motion";

const SIZE = 220;
const STROKE = 14;
const RADIUS = (SIZE - STROKE) / 2;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;

function verdict(score: number | null): { text: string; from: string; to: string } {
  if (score == null) return { text: "Сбор данных…", from: "#64748b", to: "#94a3b8" };
  if (score >= 80) return { text: "Защищено", from: "#34d399", to: "#22d3ee" };
  if (score >= 50) return { text: "Есть риски", from: "#fbbf24", to: "#fb923c" };
  return { text: "Под угрозой", from: "#fb7185", to: "#f43f5e" };
}

export function ScoreRing({ score }: { score: number | null }) {
  const { text, from, to } = verdict(score);
  const offset = CIRCUMFERENCE * (1 - (score ?? 0) / 100);

  return (
    <div className="relative" style={{ width: SIZE, height: SIZE }}>
      <div className="absolute inset-6 rounded-full blur-3xl" style={{ background: from, opacity: 0.22 }} />
      <svg width={SIZE} height={SIZE} className="relative -rotate-90">
        <defs>
          <linearGradient id="score-gradient" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stopColor={from} />
            <stop offset="100%" stopColor={to} />
          </linearGradient>
        </defs>
        <circle cx={SIZE / 2} cy={SIZE / 2} r={RADIUS} fill="none" stroke="rgb(255 255 255 / 0.07)" strokeWidth={STROKE} />
        <motion.circle
          cx={SIZE / 2}
          cy={SIZE / 2}
          r={RADIUS}
          fill="none"
          stroke="url(#score-gradient)"
          strokeWidth={STROKE}
          strokeLinecap="round"
          strokeDasharray={CIRCUMFERENCE}
          initial={{ strokeDashoffset: CIRCUMFERENCE }}
          animate={{ strokeDashoffset: offset }}
          transition={{ duration: 1.2, ease: "easeOut" }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <div className="text-6xl font-semibold tabular-nums tracking-tight">{score ?? "—"}</div>
        <div className="mt-1 text-sm text-white/60">{text}</div>
      </div>
    </div>
  );
}
