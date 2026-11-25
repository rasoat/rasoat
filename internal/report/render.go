package report

import (
	"fmt"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/rasoat/rasoat/internal/core"
	"github.com/rasoat/rasoat/internal/images"
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
	reboot, extended, notCheckedHost, hostLine, kernelLine, openNoFix, upgrade                                                                string
	scanned, dataWord, stale, fix, noFix, eol, noCves, more, summary, nothing, blocked, blockedBy, unreachable, tls, min, notChecked, checked string
	unresolved, unjudged, unjudgedMore, notJudgedBy, ruleFamily, acknowledged, discAcked, discovered, discPackages, discNothing, discSummary  string
	origin, problem, status, reason, notes                                                                                                    map[string]string
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
		reason:      map[string]string{"version-not-exact": "not an exact version: pin it or commit a lockfile", "version-hidden": "the version is not visible from outside", "not-a-listed-release": "not a release in the data (a dev build?)", "line-not-listed": "a release line the data does not list", "no-advisory-data": "no advisory data for this product yet: its versions are not judged (its end of life is, when this data has the release lines)", "image-tag-unpinned": "the tag does not name a version (latest, stable, no tag, a digest only): pin one", "distro-release-supported": "this release is supported; its packages are not judged here (rasoat host --root judges a container tree)", "line-data-not-available": "not judged: the release-line data could not be read. Run again online", "vendor-kernel": "a vendor's kernel: backports make its number say nothing, and no package here explains it", "no-package-data-for-this-distro": "not judged: this data has no per-package advisories for this distro", "package-data-not-available": "not judged: the package data could not be read. Run again online", "package-database-unreadable": "not judged: the package database could not be read", "package-database-not-found": "not judged: no package database found", "package-database-not-read": "not judged: this distro's package database is not one this program reads", "advisory-data-not-available": "not judged: the advisory data for this ecosystem could not be had. Run again online"},
		more:        "+%d more (--all or --json)",
		summary:     "%d vulnerable, %d unsupported, %d unknown, %d ok",
		nothing:     "Nothing identified: no Next.js, WordPress, Node.js, PHP or Bun version, no package in an npm, crates.io or Go lockfile, no container image or CI pin found here.",
		notJudgedBy: "no data judges this", ruleFamily: "Your rule names the family %q, which this program has no release lines for: not judged", acknowledged: "known by your rule %s: no data judges this", discAcked: ", %d known by your rules", discovered: "read", discPackages: "%s: %d packages in lockfiles (not listed here; --json lists them)", discNothing: "Nothing found: no version file, lockfile, image or CI pin.", discSummary: "%d components, %d judged by data, %d not judged by any data",
		blocked:     "The site's bot protection answered (%s). We do not try to get past it; scan the project files instead.",
		unreachable: "Could not read the site (%s).", tls: "Note: read although the HTTPS certificate chain did not verify.",
		notes:          map[string]string{"binary-bun-lock": "bun.lockb is a binary file and was not read: run `bun install --save-text-lockfile`.", "truncated": "Stopped early: too many directories. Scan a narrower path.", "kernel-belongs-to-the-container-host": "This is a container: its kernel is the host's. Run this on the host to judge the kernel.", "too-many-files": "A directory of package lists held too many files: only the first ones, in name order, were read."},
		min:            "%s: version not visible from outside; the framework needs at least %s.",
		unresolved:     "Version not readable here (a variable): %s",
		unjudged:       "Image not judged, no data for it: %s",
		unjudgedMore:   "+%s more images not judged",
		checked:        "%s: %s packages checked, %s vulnerable",
		notChecked:     "Not checked: WordPress plugins and themes, dependencies outside npm, crates.io and Go modules, other frameworks. A clean result covers only the versions listed above.",
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
		reason:      map[string]string{"version-not-exact": "chưa phải phiên bản chính xác: hãy ghim phiên bản hoặc commit lockfile", "version-hidden": "không thấy phiên bản từ bên ngoài", "not-a-listed-release": "không phải bản phát hành có trong dữ liệu (bản dev?)", "line-not-listed": "nhánh không có trong dữ liệu", "no-advisory-data": "chưa có dữ liệu khuyến cáo cho sản phẩm này: chưa kiểm tra lỗ hổng theo phiên bản (hết hỗ trợ thì có kiểm tra, khi dữ liệu có các nhánh phát hành)", "image-tag-unpinned": "tag không nêu phiên bản (latest, stable, không có tag, chỉ có digest): hãy ghim một phiên bản", "distro-release-supported": "bản phát hành này còn hỗ trợ; các gói của nó chưa được kiểm tra ở đây (rasoat host --root kiểm tra một cây container)", "line-data-not-available": "chưa kiểm tra: không đọc được dữ liệu các nhánh phát hành. Hãy chạy lại khi có mạng", "vendor-kernel": "kernel của nhà cung cấp: bản vá ngược khiến số phiên bản không nói lên gì, và không có gói nào ở đây giải thích nó", "no-package-data-for-this-distro": "chưa kiểm tra: dữ liệu này không có khuyến cáo theo gói cho bản phân phối này", "package-data-not-available": "chưa kiểm tra: không đọc được dữ liệu gói. Hãy chạy lại khi có mạng", "package-database-unreadable": "chưa kiểm tra: không đọc được cơ sở dữ liệu gói", "package-database-not-found": "chưa kiểm tra: không thấy cơ sở dữ liệu gói", "package-database-not-read": "chưa kiểm tra: chương trình chưa đọc được cơ sở dữ liệu gói của bản phân phối này", "advisory-data-not-available": "chưa kiểm tra: không có dữ liệu khuyến cáo cho hệ này. Hãy chạy lại khi có mạng"},
		more:        "còn %d mục nữa (--all hoặc --json)",
		summary:     "%d có lỗ hổng, %d hết hỗ trợ, %d chưa rõ, %d ổn",
		nothing:     "Không nhận ra gì: không thấy phiên bản Next.js, WordPress, Node.js, PHP hay Bun, không thấy gói nào trong lockfile npm, crates.io hay Go, không thấy image container hay ghim CI ở đây.",
		notJudgedBy: "không có dữ liệu nào kiểm tra", ruleFamily: "Quy tắc của bạn nêu họ %q, chương trình này chưa có dòng phát hành của họ đó: chưa kiểm tra", acknowledged: "quy tắc %s của bạn đã biết: không có dữ liệu nào kiểm tra", discAcked: ", %d đã có trong quy tắc của bạn", discovered: "đã đọc", discPackages: "%s: %d gói trong lockfile (không liệt kê ở đây; --json liệt kê)", discNothing: "Không thấy gì: không có tệp phiên bản, lockfile, image hay ghim CI.", discSummary: "%d thành phần, %d có dữ liệu kiểm tra, %d chưa có dữ liệu nào kiểm tra",
		blocked:     "Lớp chống bot của trang đã trả lời (%s). Chúng tôi không tìm cách vượt qua; hãy quét thư mục dự án.",
		unreachable: "Không đọc được trang (%s).", tls: "Lưu ý: đã đọc dù chuỗi chứng chỉ HTTPS không xác thực được.",
		notes:          map[string]string{"binary-bun-lock": "bun.lockb là tệp nhị phân nên không đọc được: hãy chạy `bun install --save-text-lockfile`.", "truncated": "Dừng sớm vì quá nhiều thư mục. Hãy quét một đường dẫn hẹp hơn.", "kernel-belongs-to-the-container-host": "Đây là container: kernel thuộc về máy chủ. Hãy chạy trên máy chủ để kiểm tra kernel.", "too-many-files": "Một thư mục danh sách gói có quá nhiều tệp: chỉ đọc những tệp đầu tiên, theo thứ tự tên."},
		min:            "%s: không thấy phiên bản từ bên ngoài; framework cần tối thiểu %s.",
		unresolved:     "Chưa đọc được phiên bản (là biến): %s",
		unjudged:       "Image chưa kiểm tra, không có dữ liệu: %s",
		unjudgedMore:   "còn %s image chưa kiểm tra nữa",
		checked:        "%s: đã kiểm tra %s gói, %s có lỗ hổng",
		notChecked:     "Chưa kiểm tra: plugin và theme WordPress, dependency ngoài npm, crates.io và Go module, framework khác. Kết quả sạch chỉ áp dụng cho các phiên bản liệt kê ở trên.",
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
		product = images.Name(strings.TrimPrefix(r.Product, "pkg:"))
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
	case len(rep.Results) == 0 && rep.Summary.OK == 0:
		out = append(out, t.nothing)
	}
	if rep.Host != nil {
		out = append(out, hostLines(rep, t)...)
	}
	shownResults, hiddenPkgs := 0, 0
	for _, r := range rep.Results {
		isPkg := strings.HasPrefix(r.Product, "pkg:")
		if !all && shownResults == maxPackages {
			if rep.Host != nil {
				out = append(out, fmt.Sprintf(t.more, len(rep.Results)-maxPackages))
				break
			}
			if isPkg { // a project can have hundreds of vulnerable packages: the worst, then a count. Next.js and WordPress always show.
				hiddenPkgs++
				continue
			}
		}
		if rep.Host != nil || isPkg {
			shownResults++
		}
		lines := renderResult(r, t, all)
		// A package gets a line and its worst advisory, unless --all.
		if !all && isPkg && len(lines) > 4 {
			lines = append(lines[:3], "  "+fmt.Sprintf(t.more, len(r.Advisories)-1))
		}
		out = append(out, lines...)
	}
	if hiddenPkgs > 0 {
		out = append(out, fmt.Sprintf(t.more, hiddenPkgs))
	}
	if rep.Site != nil && rep.Site.TLSUnverified {
		out = append(out, t.tls)
	}
	for _, n := range rep.Notes {
		if v, ok := strings.CutPrefix(n, "unresolved:"); ok {
			out = append(out, fmt.Sprintf(t.unresolved, v))
		} else if v, ok := strings.CutPrefix(n, "rule-family-unknown:"); ok {
			out = append(out, fmt.Sprintf(t.ruleFamily, v))
		} else if v, ok := strings.CutPrefix(n, "image-not-judged:"); ok {
			out = append(out, fmt.Sprintf(t.unjudged, v))
		} else if v, ok := strings.CutPrefix(n, "image-not-judged-more:"); ok {
			out = append(out, fmt.Sprintf(t.unjudgedMore, v))
		} else if m := minNote.FindStringSubmatch(n); m != nil {
			out = append(out, fmt.Sprintf(t.min, m[1], m[2]))
		} else if v, ok := strings.CutPrefix(n, "reboot-needed:"); ok {
			out = append(out, fmt.Sprintf(t.reboot, v))
		} else if v, ok := strings.CutPrefix(n, "paid-extended-support-until:"); ok {
			out = append(out, fmt.Sprintf(t.extended, v))
		} else if f := strings.Split(n, ":"); len(f) == 4 && f[0] == "packages-checked" {
			out = append(out, fmt.Sprintf(t.checked, f[1], f[2], f[3]))
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
	if len(rep.Results) > 0 || rep.Summary.OK > 0 {
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

// Clean takes the control characters out of text a terminal would act on.
func Clean(s string) string { return controls.ReplaceAllString(s, "") }
