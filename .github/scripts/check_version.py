#!/usr/bin/env python3
"""
GnuPG Version Checker
- 爬取 https://www.gnupg.org/download/index.html 获取最新稳定版信息
- 输出 JSON 供 GitHub Actions 使用
"""

import json
import re
import sys
from html.parser import HTMLParser
from urllib.request import Request, urlopen
from urllib.parse import urljoin


BASE_URL = "https://www.gnupg.org"
DOWNLOAD_URL = "https://www.gnupg.org/download/index.html"

REQUEST_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Accept-Language": "zh-CN,zh;q=0.9,zh-TW;q=0.8,zh-HK;q=0.7,en-US;q=0.6,en;q=0.5",
    "Cache-Control": "no-cache",
    "Connection": "keep-alive",
    "Host": "www.gnupg.org",
    "Pragma": "no-cache",
    "Priority": "u=0, i",
    "Referer": "https://www.gnupg.org/download/index.html",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "same-origin",
    "Sec-Fetch-User": "?1",
    "Upgrade-Insecure-Requests": "1",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:152.0) Gecko/20100101 Firefox/152.0",
}


class TableParser(HTMLParser):
    """解析 GnuPG 下载页的源代码发布表格"""

    def __init__(self):
        super().__init__()
        self.reset()
        self.in_table = False
        self.in_row = False
        self.in_cell = False
        self.in_thead = False
        self.in_tbody = False
        self.in_a = False
        self.current_cell_tag = None
        self.current_cell_data = {}
        self.current_cell_key = None
        self.cell_index = 0
        self.col_index = 0
        self.current_link_url = ""
        self.current_link_text = ""
        self.rows = []
        self.current_row = []
        self.table_count = 0
        self.found_source_table = False
        self.collect_text = False
        self.cell_text = ""
        self.link_in_current_cell = False
        self.tbody_count = 0

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)

        if tag == "table":
            self.table_count += 1
            # 第一个表格是源代码发布表
            if self.table_count == 1:
                self.in_table = True
                self.rows = []
                self.in_thead = False
                self.in_tbody = False

        if self.in_table:
            if tag == "thead":
                self.in_thead = True
            elif tag == "tbody":
                self.in_tbody = True

            if tag == "tr":
                self.in_row = True
                self.current_row = []
                self.col_index = 0

            if self.in_row and tag in ("th", "td"):
                self.in_cell = True
                self.current_cell_tag = tag
                self.cell_text = ""
                self.link_in_current_cell = False
                self.current_link_url = ""

            if self.in_cell and tag == "a":
                self.in_a = True
                self.link_in_current_cell = True
                self.current_link_url = attrs_dict.get("href", "")
                self.current_link_text = ""

    def handle_endtag(self, tag):
        if self.in_cell and tag in ("th", "td"):
            self.in_cell = False
            cell_value = self.cell_text.strip()
            if self.link_in_current_cell and self.current_link_url:
                cell_value = {
                    "text": cell_value,
                    "url": urljoin(BASE_URL, self.current_link_url),
                }
            self.current_row.append(cell_value)
            self.col_index += 1

        if tag == "a":
            self.in_a = False

        if tag == "tr" and self.in_row:
            self.in_row = False
            if len(self.current_row) >= 4:
                self.rows.append(self.current_row)

        if tag == "table" and self.in_table:
            self.in_table = False

    def handle_data(self, data):
        if self.in_cell:
            self.cell_text += data
        if self.in_a:
            self.current_link_text += data


def fetch_page(url):
    """下载页面内容"""
    req = Request(url, headers=REQUEST_HEADERS)
    with urlopen(req) as resp:
        charset = resp.headers.get_content_charset() or "utf-8"
        return resp.read().decode(charset, errors="replace")


def parse_version_table(html):
    """解析 HTML 中的源代码发布表格"""
    parser = TableParser()
    parser.feed(html)
    return parser.rows


def extract_download_info(rows):
    """
    从表格行提取结构化下载信息
    返回: {
        "gnupg_stable": { "version", "date", "tarball_url", "sig_url", "size" },
        "gnupg_w32": { ... },  # stable with libs
        "dependencies": [ ... ]
    }
    """
    result = {
        "gnupg_stable": None,
        "gnupg_stable_with_libs": None,
        "dependencies": [],
    }

    # 已知的依赖包名（按表格顺序）
    dep_names = [
        "Libgpg-error",
        "Libgcrypt",
        "Libksba",
        "Libassuan",
        "ntbTLS",
        "nPth",
    ]

    dep_idx = 0
    for row in rows:
        if len(row) < 6:
            continue

        name_cell = row[0]
        version = str(row[1]).strip()
        date = str(row[2]).strip()
        size = str(row[3]).strip()
        tarball = row[4]
        signature = row[5]

        if isinstance(name_cell, dict):
            name = name_cell["text"].strip()
        else:
            name = str(name_cell).strip()

        # 解析下载链接
        tarball_url = tarball["url"] if isinstance(tarball, dict) else None
        sig_url = signature["url"] if isinstance(signature, dict) else None

        # 提取 tarball 文件名
        tarball_name = ""
        if tarball_url:
            tarball_name = tarball_url.rstrip("/").split("/")[-1]

        entry = {
            "name": name,
            "version": version,
            "date": date,
            "size": size,
            "tarball_name": tarball_name,
            "tarball_url": tarball_url,
            "sig_url": sig_url,
        }

        if "GnuPG (stable)" in name and "with libs" not in name:
            result["gnupg_stable"] = entry
        elif "GnuPG (stable with libs)" in name:
            result["gnupg_stable_with_libs"] = entry
        else:
            # 匹配依赖包
            if dep_idx < len(dep_names):
                expected = dep_names[dep_idx]
                if name == expected or name.startswith(expected):
                    entry["component"] = expected.lower().replace("-", "_")
                    result["dependencies"].append(entry)
                    dep_idx += 1

    return result


def main():
    """主函数"""
    try:
        print(f"Fetching {DOWNLOAD_URL} ...", file=sys.stderr)
        html = fetch_page(DOWNLOAD_URL)
        print(f"Got {len(html)} bytes", file=sys.stderr)

        rows = parse_version_table(html)
        print(f"Parsed {len(rows)} table rows", file=sys.stderr)

        info = extract_download_info(rows)

        if info["gnupg_stable"]:
            ver = info["gnupg_stable"]["version"]
            print(f"Found GnuPG stable version: {ver}", file=sys.stderr)
        else:
            print("WARNING: Could not find GnuPG stable entry!", file=sys.stderr)

        # 输出 JSON 到 stdout
        output = {
            "version": info["gnupg_stable"]["version"] if info["gnupg_stable"] else "",
            "date": info["gnupg_stable"]["date"] if info["gnupg_stable"] else "",
            "tarball_url": info["gnupg_stable"]["tarball_url"] if info["gnupg_stable"] else "",
            "tarball_name": info["gnupg_stable"]["tarball_name"] if info["gnupg_stable"] else "",
            "sig_url": info["gnupg_stable"]["sig_url"] if info["gnupg_stable"] else "",
            "w32_tarball_url": info["gnupg_stable_with_libs"]["tarball_url"] if info["gnupg_stable_with_libs"] else "",
            "w32_tarball_name": info["gnupg_stable_with_libs"]["tarball_name"] if info["gnupg_stable_with_libs"] else "",
            "dependencies": info["dependencies"],
        }
        print(json.dumps(output, indent=2, ensure_ascii=False))
        return 0

    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
