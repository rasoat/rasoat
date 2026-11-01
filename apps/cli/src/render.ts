// The terminal view of a Report, in Vietnamese or English. Everything printed passes clean(): advisory text and site
// answers are third-party data and must not reach the terminal as control sequences.
import { PRODUCT_NAMES, type Status } from "@rasoat/core";
import type { Report, Result } from "./report.ts";

export type Lang = "vi" | "en";
export const langFromEnv = (env: Record<string, string | undefined>): Lang => (/^vi/i.test(env.LC_ALL || env.LC_MESSAGES || env.LANG || "") ? "vi" : "en");

const clean = (s: string) => s.replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/g, "");
const MAX_SHOWN = 5;

const TEXT = {
  en: {
    scanning: "scanned", data: (d: string, how: string) => `data ${d} (${how})`,
    origin: { downloaded: "just downloaded", cached: "cached", bundled: "built into this binary" },
    stale: (n: number) => `Warning: the data is ${n} days old. Run again online for current advisories.`,
    problem: { unreachable: "could not download new data", invalid: "the downloaded data was malformed and was not used", older: "the downloaded data was older and was not used", "lost-records": "the downloaded data had lost records and was not used" },
    status: { vulnerable: "VULNERABLE", unsupported: "UNSUPPORTED", ok: "ok", unknown: "UNKNOWN" } as Record<Status, string>,
    fix: "upgrade to", noFix: "no published release clears every advisory; move to a newer line",
    eol: "this line gets no more security fixes",
    noCves: "WordPress.org marks this release insecure; NVD has no range for the missing fixes yet",
    reason: { "version-not-exact": "not an exact version: pin it or commit a lockfile", "version-hidden": "the version is not visible from outside", "not-a-listed-release": "not a release in the data (a dev build?)", "line-not-listed": "a release line the data does not list" },
    more: (n: number) => `+${n} more (--all or --json)`,
    summary: (s: Report["summary"]) => `${s.vulnerable} vulnerable, ${s.unsupported} unsupported, ${s.unknown} unknown, ${s.ok} ok`,
    nothing: "Nothing identified: no Next.js, WordPress, Node.js, PHP or Bun version found here.",
    site: { blocked: (st: number | null, by: string | null) => `The site's bot protection answered (${st}${by ? `, ${by}` : ""}). We do not try to get past it; scan the project files instead.`, unreachable: (st: number | null, cause: string | null) => `Could not read the site (${st ?? cause}).`, tls: "Note: read although the HTTPS certificate chain did not verify." },
    notes: { "binary-bun-lock": "bun.lockb is a binary file and was not read: run `bun install --save-text-lockfile`.", truncated: "Stopped early: too many directories. Scan a narrower path." } as Record<string, string>,
    min: (rt: string, v: string) => `${rt}: version not visible from outside; the framework needs at least ${v}.`,
    notChecked: "Not checked: WordPress plugins and themes, other dependencies, other frameworks. A clean result covers only the versions listed above.",
  },
  vi: {
    scanning: "đã quét", data: (d: string, how: string) => `dữ liệu ${d} (${how})`,
    origin: { downloaded: "vừa tải", cached: "bản lưu", bundled: "kèm trong bản cài" },
    stale: (n: number) => `Cảnh báo: dữ liệu đã cũ ${n} ngày. Hãy chạy lại khi có mạng để có khuyến cáo mới.`,
    problem: { unreachable: "không tải được dữ liệu mới", invalid: "dữ liệu tải về bị lỗi nên không dùng", older: "dữ liệu tải về cũ hơn nên không dùng", "lost-records": "dữ liệu tải về bị thiếu bản ghi nên không dùng" },
    status: { vulnerable: "CÓ LỖ HỔNG", unsupported: "HẾT HỖ TRỢ", ok: "ổn", unknown: "CHƯA RÕ" } as Record<Status, string>,
    fix: "nâng lên", noFix: "chưa có bản phát hành nào vá hết các lỗ hổng; hãy chuyển sang nhánh mới hơn",
    eol: "nhánh này không còn nhận bản vá bảo mật",
    noCves: "WordPress.org đánh dấu bản này không an toàn; NVD chưa ghi khoảng phiên bản cho các bản vá còn thiếu",
    reason: { "version-not-exact": "chưa phải phiên bản chính xác: hãy ghim phiên bản hoặc commit lockfile", "version-hidden": "không thấy phiên bản từ bên ngoài", "not-a-listed-release": "không phải bản phát hành có trong dữ liệu (bản dev?)", "line-not-listed": "nhánh không có trong dữ liệu" },
    more: (n: number) => `còn ${n} mục nữa (--all hoặc --json)`,
    summary: (s: Report["summary"]) => `${s.vulnerable} có lỗ hổng, ${s.unsupported} hết hỗ trợ, ${s.unknown} chưa rõ, ${s.ok} ổn`,
    nothing: "Không nhận ra gì: không thấy phiên bản Next.js, WordPress, Node.js, PHP hay Bun ở đây.",
    site: { blocked: (st: number | null, by: string | null) => `Lớp chống bot của trang đã trả lời (${st}${by ? `, ${by}` : ""}). Chúng tôi không tìm cách vượt qua; hãy quét thư mục dự án.`, unreachable: (st: number | null, cause: string | null) => `Không đọc được trang (${st ?? cause}).`, tls: "Lưu ý: đã đọc dù chuỗi chứng chỉ HTTPS không xác thực được." },
    notes: { "binary-bun-lock": "bun.lockb là tệp nhị phân nên không đọc được: hãy chạy `bun install --save-text-lockfile`.", truncated: "Dừng sớm vì quá nhiều thư mục. Hãy quét một đường dẫn hẹp hơn." } as Record<string, string>,
    min: (rt: string, v: string) => `${rt}: không thấy phiên bản từ bên ngoài; framework cần tối thiểu ${v}.`,
    notChecked: "Chưa kiểm tra: plugin và theme WordPress, các dependency khác, framework khác. Kết quả sạch chỉ áp dụng cho các phiên bản liệt kê ở trên.",
  },
};

function result(r: Result, lang: Lang, all: boolean): string[] {
  const t = TEXT[lang];
  const name = `${PRODUCT_NAMES[r.product]} ${r.version ?? ""}`.trim();
  const lines = [`${t.status[r.status].padEnd(12)} ${name}  ${r.sources.join(", ")}${r.how ? ` [${r.how}]` : ""}`];
  if (r.status === "ok") return lines;
  if (r.reason) lines.push(`  ${t.reason[r.reason]}`);
  if (r.status === "unsupported") lines.push(`  ${t.eol}`);
  if (r.fix) lines.push(`  ${t.fix} ${r.fix}`);
  else if (r.noFix) lines.push(`  ${t.noFix}`);
  if (r.status === "vulnerable" && r.product === "wordpress" && !r.advisories.length) lines.push(`  ${t.noCves}`);
  for (const a of all ? r.advisories : r.advisories.slice(0, MAX_SHOWN)) lines.push(`  ${a.severity.padEnd(8)} ${a.id}  ${a.summary.slice(0, 90)}  ${a.url}`);
  if (!all && r.advisories.length > MAX_SHOWN) lines.push(`  ${t.more(r.advisories.length - MAX_SHOWN)}`);
  return lines;
}

export function render(rep: Report, lang: Lang, all: boolean): string {
  const t = TEXT[lang];
  const out = [`${rep.tool.name} ${rep.tool.version}: ${t.scanning} ${rep.target.value}, ${t.data(rep.data.built, t.origin[rep.data.origin])}`];
  if (rep.data.problem) out.push(t.problem[rep.data.problem]);
  if (rep.data.stale) out.push(t.stale(rep.data.age_days));
  out.push("");
  if (rep.site?.outcome === "blocked") out.push(t.site.blocked(rep.site.status, rep.site.by));
  else if (rep.site?.outcome === "unreachable") out.push(t.site.unreachable(rep.site.status, rep.site.cause));
  else if (!rep.results.length) out.push(t.nothing);
  for (const r of rep.results) out.push(...result(r, lang, all));
  if (rep.site?.tls_unverified) out.push(t.site.tls);
  for (const n of rep.notes) {
    const min = n.match(/^(\w+)-min:(.+)$/);
    out.push(min ? t.min(min[1]!, min[2]!) : (t.notes[n] ?? n));
  }
  if (rep.results.length) out.push("", t.summary(rep.summary));
  out.push("", t.notChecked, ...rep.notices);
  return clean(out.join("\n"));
}
