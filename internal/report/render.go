package report

import (
	"fmt"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/rasoat/rasoat/internal/core"
)

// LangFromEnv: Vietnamese when the locale says so.
func LangFromEnv() string {
	for _, k := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if v := os.Getenv(k); v != "" {
			if len(v) >= 2 && strings.EqualFold(v[:2], "vi") {
				return "vi"
			}
			return "en"
		}
	}
	return "en"
}

var controls = core.NewRe(`[\x{0000}-\x{0008}\x{000b}-\x{001f}\x{007f}-\x{009f}]`)

const (
	maxShown    = 5
	maxPackages = 25 // a machine can have hundreds of findings: the worst, then a count
)

type text struct {
	reboot, extended, notCheckedHost, hostLine, kernelLine, openNoFix, upgrade                                                       string
	scanned, dataWord, stale, fix, noFix, eol, noCves, more, summary, nothing, blocked, blockedBy, unreachable, tls, min, notChecked string
	origin, problem, status, reason, notes                                                                                           map[string]string
}

var texts = map[string]text{
	"en": {
		scanned: "scanned", dataWord: "data",
		origin:  map[string]string{"downloaded": "just downloaded", "cached": "cached", "bundled": "built into this binary"},
		stale:   "Warning: the data is %d days old. Run again online for current advisories.",
		problem: map[string]string{"unreachable": "could not download new data", "invalid": "the downloaded data was malformed and was not used", "older": "the downloaded data was older and was not used", "lost-records": "the downloaded data had lost records and was not used"},
		status:  map[string]string{"vulnerable": "VULNERABLE", "unsupported": "UNSUPPORTED", "ok": "ok", "unknown": "UNKNOWN"},
		fix:     "upgrade to", noFix: "no published release clears every advisory; move to a newer line",
		eol:         "this line gets no more security fixes",
		noCves:      "WordPress.org marks this release insecure; NVD has no range for the missing fixes yet",
		reason:      map[string]string{"version-not-exact": "not an exact version: pin it or commit a lockfile", "version-hidden": "the version is not visible from outside", "not-a-listed-release": "not a release in the data (a dev build?)", "line-not-listed": "a release line the data does not list", "vendor-kernel": "a vendor's kernel: backports make its number say nothing, and no package here explains it", "no-package-data-for-this-distro": "not judged: this data has no per-package advisories for this distro", "package-data-not-available": "not judged: the package data could not be read. Run again online", "package-database-unreadable": "not judged: the package database could not be read", "package-database-not-found": "not judged: no package database found", "package-database-not-read": "not judged: this distro's package database is not one this program reads"},
		more:        "+%d more (--all or --json)",
		summary:     "%d vulnerable, %d unsupported, %d unknown, %d ok",
		nothing:     "Nothing identified: no Next.js, WordPress, Node.js, PHP or Bun version found here.",
		blocked:     "The site's bot protection answered (%s). We do not try to get past it; scan the project files instead.",
		unreachable: "Could not read the site (%s).", tls: "Note: read although the HTTPS certificate chain did not verify.",
		notes:          map[string]string{"binary-bun-lock": "bun.lockb is a binary file and was not read: run `bun install --save-text-lockfile`.", "truncated": "Stopped early: too many directories. Scan a narrower path.", "kernel-belongs-to-the-container-host": "This is a container: its kernel is the host's. Run this on the host to judge the kernel."},
		min:            "%s: version not visible from outside; the framework needs at least %s.",
		notChecked:     "Not checked: WordPress plugins and themes, other dependencies, other frameworks. A clean result covers only the versions listed above.",
		notCheckedHost: "Not checked: software installed outside the package manager, whether a flaw is reachable on this machine, kernel configuration, project dependencies. A clean result means no published fix is missing, in this data.",
		extended:       "Paid extended support for this release runs until %s, if you have it: this data does not see those fixes.",
		reboot:         "A newer kernel is installed (%s) but not running: reboot to use it.",
		hostLine:       "%s: %d packages read",
		kernelLine:     "Kernel running %s, newest installed %s",
		openNoFix:      "%d published CVEs reach installed packages with no fix yet. They are counted, not listed.",
		upgrade:        "To upgrade what is listed: %s",
	},
	"vi": {
		scanned: "đã quét", dataWord: "dữ liệu",
		origin:  map[string]string{"downloaded": "vừa tải", "cached": "bản lưu", "bundled": "kèm trong bản cài"},
		stale:   "Cảnh báo: dữ liệu đã cũ %d ngày. Hãy chạy lại khi có mạng để có khuyến cáo mới.",
		problem: map[string]string{"unreachable": "không tải được dữ liệu mới", "invalid": "dữ liệu tải về bị lỗi nên không dùng", "older": "dữ liệu tải về cũ hơn nên không dùng", "lost-records": "dữ liệu tải về bị thiếu bản ghi nên không dùng"},
		status:  map[string]string{"vulnerable": "CÓ LỖ HỔNG", "unsupported": "HẾT HỖ TRỢ", "ok": "ổn", "unknown": "CHƯA RÕ"},
		fix:     "nâng lên", noFix: "chưa có bản phát hành nào vá hết các lỗ hổng; hãy chuyển sang nhánh mới hơn",
		eol:         "nhánh này không còn nhận bản vá bảo mật",
		noCves:      "WordPress.org đánh dấu bản này không an toàn; NVD chưa ghi khoảng phiên bản cho các bản vá còn thiếu",
		reason:      map[string]string{"version-not-exact": "chưa phải phiên bản chính xác: hãy ghim phiên bản hoặc commit lockfile", "version-hidden": "không thấy phiên bản từ bên ngoài", "not-a-listed-release": "không phải bản phát hành có trong dữ liệu (bản dev?)", "line-not-listed": "nhánh không có trong dữ liệu", "vendor-kernel": "kernel của nhà cung cấp: bản vá ngược khiến số phiên bản không nói lên gì, và không có gói nào ở đây giải thích nó", "no-package-data-for-this-distro": "chưa kiểm tra: dữ liệu này không có khuyến cáo theo gói cho bản phân phối này", "package-data-not-available": "chưa kiểm tra: không đọc được dữ liệu gói. Hãy chạy lại khi có mạng", "package-database-unreadable": "chưa kiểm tra: không đọc được cơ sở dữ liệu gói", "package-database-not-found": "chưa kiểm tra: không thấy cơ sở dữ liệu gói", "package-database-not-read": "chưa kiểm tra: chương trình chưa đọc được cơ sở dữ liệu gói của bản phân phối này"},
		more:        "còn %d mục nữa (--all hoặc --json)",
		summary:     "%d có lỗ hổng, %d hết hỗ trợ, %d chưa rõ, %d ổn",
		nothing:     "Không nhận ra gì: không thấy phiên bản Next.js, WordPress, Node.js, PHP hay Bun ở đây.",
		blocked:     "Lớp chống bot của trang đã trả lời (%s). Chúng tôi không tìm cách vượt qua; hãy quét thư mục dự án.",
		unreachable: "Không đọc được trang (%s).", tls: "Lưu ý: đã đọc dù chuỗi chứng chỉ HTTPS không xác thực được.",
		notes:          map[string]string{"binary-bun-lock": "bun.lockb là tệp nhị phân nên không đọc được: hãy chạy `bun install --save-text-lockfile`.", "truncated": "Dừng sớm vì quá nhiều thư mục. Hãy quét một đường dẫn hẹp hơn.", "kernel-belongs-to-the-container-host": "Đây là container: kernel thuộc về máy chủ. Hãy chạy trên máy chủ để kiểm tra kernel."},
		min:            "%s: không thấy phiên bản từ bên ngoài; framework cần tối thiểu %s.",
		notChecked:     "Chưa kiểm tra: plugin và theme WordPress, các dependency khác, framework khác. Kết quả sạch chỉ áp dụng cho các phiên bản liệt kê ở trên.",
		notCheckedHost: "Chưa kiểm tra: phần mềm cài ngoài trình quản lý gói, lỗ hổng có khai thác được trên máy này không, cấu hình kernel, dependency của dự án. Kết quả sạch nghĩa là không thiếu bản vá đã công bố, theo dữ liệu này.",
		extended:       "Hỗ trợ mở rộng trả phí cho bản này kéo dài đến %s, nếu bạn có: dữ liệu này không thấy các bản vá đó.",
		reboot:         "Đã cài kernel mới hơn (%s) nhưng chưa chạy: hãy khởi động lại để dùng.",
		hostLine:       "%s: đã đọc %d gói",
		kernelLine:     "Kernel đang chạy %s, bản mới nhất đã cài %s",
		openNoFix:      "%d CVE đã công bố ảnh hưởng đến gói đã cài nhưng chưa có bản vá. Chỉ đếm, không liệt kê.",
		upgrade:        "Để nâng cấp các gói đã liệt kê: %s",
	},
}

func pad(s string, n int) string {
	if c := utf8.RuneCountInString(s); c < n {
		return s + strings.Repeat(" ", n-c)
	}
	return s
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func renderResult(r Result, t text, all bool) []string {
	product := core.ProductNames[r.Product]
	if product == "" {
		product = strings.TrimPrefix(r.Product, "pkg:")
	}
	name := strings.TrimSpace(product + " " + deref(r.Version))
	how := ""
	if r.How != nil {
		how = " [" + *r.How + "]"
	}
	lines := []string{pad(t.status[r.Status], 12) + " " + name + "  " + strings.Join(r.Sources, ", ") + how}
	if r.Status == core.OK {
		return lines
	}
	if r.Reason != nil {
		lines = append(lines, "  "+t.reason[*r.Reason])
	}
	if r.Status == core.Unsupported {
		lines = append(lines, "  "+t.eol)
	}
	if r.Fix != nil {
		lines = append(lines, "  "+t.fix+" "+*r.Fix)
	} else if r.NoFix {
		lines = append(lines, "  "+t.noFix)
	}
	if r.Status == core.Vulnerable && r.Product == "wordpress" && len(r.Advisories) == 0 {
		lines = append(lines, "  "+t.noCves)
	}
	shown := r.Advisories
	if !all && len(shown) > maxShown {
		shown = shown[:maxShown]
	}
	for _, a := range shown {
		text := "  "
		if a.Summary != "" {
			text = "  " + short(a.Summary, 90) + "  "
		}
		lines = append(lines, "  "+pad(a.Severity, 8)+" "+a.ID+text+a.URL)
	}
	if !all && len(r.Advisories) > maxShown {
		lines = append(lines, "  "+fmt.Sprintf(t.more, len(r.Advisories)-maxShown))
	}
	return lines
}

var minNote = core.NewRe(`^(\w+)-min:(.+)$`)

func hostLines(rep *Report, t text) []string {
	h := rep.Host
	out := []string{fmt.Sprintf(t.hostLine, h.Name, h.Packages)}
	if h.KernelRunning != nil && h.KernelNewest != nil {
		out = append(out, fmt.Sprintf(t.kernelLine, *h.KernelRunning, *h.KernelNewest))
	}
	return append(out, "")
}

// Render is the terminal view. Everything printed passes the control filter: advisory text and site answers are
// third-party data and must not reach the terminal as control sequences.
func Render(rep *Report, lang string, all bool) string {
	t := texts[lang]
	out := []string{fmt.Sprintf("%s %s: %s %s, %s %s (%s)", rep.Tool.Name, rep.Tool.Version, t.scanned, rep.Target.Value, t.dataWord, rep.Data.Built, t.origin[rep.Data.Origin])}
	if rep.Data.Problem != nil {
		out = append(out, t.problem[*rep.Data.Problem])
	}
	if rep.Data.Stale {
		out = append(out, fmt.Sprintf(t.stale, rep.Data.AgeDays))
	}
	out = append(out, "")
	switch {
	case rep.Site != nil && rep.Site.Outcome == "blocked":
		what := fmt.Sprint(*rep.Site.Status)
		if rep.Site.By != nil {
			what += ", " + *rep.Site.By
		}
		out = append(out, fmt.Sprintf(t.blocked, what))
	case rep.Site != nil && rep.Site.Outcome == "unreachable":
		what := deref(rep.Site.Cause)
		if rep.Site.Status != nil {
			what = fmt.Sprint(*rep.Site.Status)
		}
		out = append(out, fmt.Sprintf(t.unreachable, what))
	case len(rep.Results) == 0:
		out = append(out, t.nothing)
	}
	if rep.Host != nil {
		out = append(out, hostLines(rep, t)...)
	}
	shownResults := 0
	for _, r := range rep.Results {
		if rep.Host != nil && !all && shownResults == maxPackages {
			out = append(out, fmt.Sprintf(t.more, len(rep.Results)-maxPackages))
			break
		}
		shownResults++
		lines := renderResult(r, t, all)
		// On a machine each package gets a line and its worst advisory, unless --all.
		if rep.Host != nil && !all && strings.HasPrefix(r.Product, "pkg:") && len(lines) > 4 {
			lines = append(lines[:3], "  "+fmt.Sprintf(t.more, len(r.Advisories)-1))
		}
		out = append(out, lines...)
	}
	if rep.Site != nil && rep.Site.TLSUnverified {
		out = append(out, t.tls)
	}
	for _, n := range rep.Notes {
		if m := minNote.FindStringSubmatch(n); m != nil {
			out = append(out, fmt.Sprintf(t.min, m[1], m[2]))
		} else if v, ok := strings.CutPrefix(n, "reboot-needed:"); ok {
			out = append(out, fmt.Sprintf(t.reboot, v))
		} else if v, ok := strings.CutPrefix(n, "paid-extended-support-until:"); ok {
			out = append(out, fmt.Sprintf(t.extended, v))
		} else if s, ok := t.notes[n]; ok {
			out = append(out, s)
		} else {
			out = append(out, n)
		}
	}
	if rep.Host != nil {
		if rep.Host.OpenNoFix > 0 {
			out = append(out, "", fmt.Sprintf(t.openNoFix, rep.Host.OpenNoFix))
		}
		if rep.Host.UpgradeCmd != nil {
			out = append(out, "", fmt.Sprintf(t.upgrade, *rep.Host.UpgradeCmd))
		}
	}
	if len(rep.Results) > 0 {
		out = append(out, "", fmt.Sprintf(t.summary, rep.Summary.Vulnerable, rep.Summary.Unsupported, rep.Summary.Unknown, rep.Summary.OK))
	}
	if rep.Host != nil {
		out = append(out, "", t.notCheckedHost)
	} else {
		out = append(out, "", t.notChecked)
	}
	out = append(out, rep.Notices...)
	return controls.ReplaceAllString(strings.Join(out, "\n"), "")
}
