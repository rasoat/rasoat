package localdb

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

type words struct {
	title, none, bundled, age, stale, records, plan, updated string
	result, problems                                         map[string]string
}

var texts = map[string]words{
	"en": {
		title: "local data in %s", none: "not cached", bundled: "built into this binary", age: "%d days old", stale: "STALE", records: "%d records",
		plan:     "Also downloading %d distro release files (%d records; the index does not carry file sizes).",
		updated:  "%d files checked, %d changed.",
		result:   map[string]string{"added": "added", "updated": "updated", "unchanged": "unchanged", "kept": "kept"},
		problems: map[string]string{"unreachable": "could not download", "invalid": "the download was malformed and was not used", "older": "the download was older and was not used", "lost-records": "the download had lost records and was not used", "index-not-available": "the index is not available, so no distro file is known"},
	},
	"vi": {
		title: "dữ liệu cục bộ trong %s", none: "chưa có trong bản lưu", bundled: "kèm trong bản cài", age: "cũ %d ngày", stale: "CŨ", records: "%d bản ghi",
		plan:     "Tải thêm %d tệp của các bản phân phối (%d bản ghi; chỉ mục không ghi dung lượng tệp).",
		updated:  "đã kiểm tra %d tệp, %d tệp đổi.",
		result:   map[string]string{"added": "thêm mới", "updated": "đã cập nhật", "unchanged": "không đổi", "kept": "giữ bản cũ"},
		problems: map[string]string{"unreachable": "không tải được", "invalid": "bản tải về bị lỗi nên không dùng", "older": "bản tải về cũ hơn nên không dùng", "lost-records": "bản tải về bị thiếu bản ghi nên không dùng", "index-not-available": "không có chỉ mục nên không biết có tệp bản phân phối nào"},
	},
}

func pad(s string, n int) string {
	if c := utf8.RuneCountInString(s); c < n {
		return s + strings.Repeat(" ", n-c)
	}
	return s
}

func lang(l string) words {
	if t, ok := texts[l]; ok {
		return t
	}
	return texts["en"]
}

// RenderStatus is the terminal view of Status.
func RenderStatus(s Status, l string) string {
	t := lang(l)
	out := []string{fmt.Sprintf("%s %s: "+t.title, s.Tool.Name, s.Tool.Version, s.Cache), ""}
	for _, f := range s.Files {
		line := pad(f.Name, 24) + pad(f.Kind, 11)
		switch {
		case f.Origin == "none":
			line += t.none
		default:
			line += pad(f.Built, 11) + pad(fmt.Sprintf(t.records, f.Records), 16) + fmt.Sprintf(t.age, *f.AgeDays)
			if f.Stale {
				line += "  " + t.stale
			}
			if f.Origin == "bundled" {
				line += "  (" + t.bundled + ")"
			}
		}
		out = append(out, line)
		if f.Origin != "bundled" {
			out = append(out, "    "+f.Path)
		}
	}
	return strings.Join(out, "\n")
}

// RenderPlan is said before the distro files come.
func RenderPlan(p Plan, l string) string { return fmt.Sprintf(lang(l).plan, p.Files, p.Records) }

// RenderUpdate is the terminal view of what an update did.
func RenderUpdate(u Updated, l string) string {
	t := lang(l)
	var out []string
	changes := 0
	for _, c := range u.Files {
		line := pad(c.Name, 24) + pad(t.result[c.Result], 13)
		switch {
		case c.Problem != nil:
			line += t.problems[*c.Problem]
		case c.Result == "added":
			line += fmt.Sprintf("%s, "+t.records, c.BuiltAfter, c.RecordsAfter)
		case c.Result == "updated":
			line += fmt.Sprintf("%s -> %s, "+t.records, c.BuiltBefore, c.BuiltAfter, c.RecordsAfter)
		default:
			line += fmt.Sprintf("%s, "+t.records, c.BuiltAfter, c.RecordsAfter)
		}
		if c.Result == "added" || c.Result == "updated" {
			changes++
		}
		out = append(out, line)
	}
	return strings.Join(append(out, "", fmt.Sprintf(t.updated, len(u.Files), changes)), "\n")
}
