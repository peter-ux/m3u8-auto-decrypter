"""
M3U8 Segment Merger (로컬 파일 버전)
- txt의 URI가 URL이어도 파일명만 추출해서 로컬에서 찾습니다.
- AES-128 암호화 자동 복호화 후 병합.

사용법:
  python m3u8_merger.py playlist.txt
  python m3u8_merger.py C:/path/to/playlist.txt -d D:/segments -k D:/keys/encryption.key -o D:/out/result.ts
"""

import sys
import argparse
from pathlib import Path
from urllib.parse import urlparse
from Crypto.Cipher import AES


def uri_to_filename(uri: str) -> str:
    """URL이든 로컬 경로든 파일명만 추출 (쿼리스트링 제거)"""
    parsed = urlparse(uri)
    if parsed.scheme in ("http", "https"):
        return Path(parsed.path).name
    return Path(uri).name


def parse_key_tag(tag: str) -> dict:
    """#EXT-X-KEY:METHOD=AES-128,URI="...",IV=0x... 파싱"""
    result = {}
    attrs = tag[len("#EXT-X-KEY:"):].strip()

    parts, buf, in_quote = [], "", False
    for ch in attrs:
        if ch == '"':
            in_quote = not in_quote
        elif ch == ',' and not in_quote:
            parts.append(buf); buf = ""; continue
        buf += ch
    parts.append(buf)

    for part in parts:
        if '=' in part:
            k, v = part.split('=', 1)
            result[k.strip()] = v.strip().strip('"')
    return result


def split_m3u8_content(content: str) -> list:
    """줄바꿈 없이 # 태그들이 붙어있는 경우도 처리."""
    lines = []
    for raw_line in content.splitlines():
        raw_line = raw_line.strip()
        if not raw_line:
            continue
        while raw_line:
            if raw_line.startswith("#"):
                next_hash = raw_line.find("#", 1)
                if next_hash == -1:
                    lines.append(raw_line); raw_line = ""
                else:
                    lines.append(raw_line[:next_hash]); raw_line = raw_line[next_hash:]
            else:
                next_hash = raw_line.find("#")
                if next_hash == -1:
                    lines.append(raw_line); raw_line = ""
                else:
                    lines.append(raw_line[:next_hash]); raw_line = raw_line[next_hash:]
    return [l.strip() for l in lines if l.strip()]


def parse_m3u8(txt_path: Path) -> list:
    content = txt_path.read_text(encoding="utf-8")
    lines = split_m3u8_content(content)

    if not any(l.startswith("#EXTM3U") for l in lines):
        raise ValueError("유효한 #EXTM3U 파일이 아닙니다.")

    segments = []
    current_key = None
    seq = 0

    for line in lines:
        if line.startswith("#EXT-X-KEY:"):
            current_key = parse_key_tag(line)
        elif line.startswith("#EXT-X-MEDIA-SEQUENCE:"):
            seq = int(line.split(":", 1)[1].strip())
        elif not line.startswith("#"):
            segments.append({
                "uri":      line,
                "filename": uri_to_filename(line),
                "key":      current_key,
                "seq":      seq,
            })
            seq += 1

    return segments


def load_key(key_info: dict, base_dir: Path, key_override: Path = None) -> bytes:
    if key_override:
        key_path = key_override
    else:
        key_filename = uri_to_filename(key_info["URI"])
        key_path = base_dir / key_filename

    if not key_path.exists():
        raise FileNotFoundError(
            f"키 파일을 찾을 수 없습니다: {key_path}\n"
            f"  hint: -k 옵션으로 키 파일 경로를 직접 지정하거나,\n"
            f"        '{key_path.name}' 파일을 {base_dir} 에 두세요."
        )

    print(f"  🔑 키 파일: {key_path}")
    return key_path.read_bytes()


def decrypt_aes128(data: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    dec = cipher.decrypt(data)
    pad = dec[-1]
    if 1 <= pad <= 16:
        dec = dec[:-pad]
    return dec


def merge(txt_path: Path, output_path: Path, base_dir: Path = None, key_override: Path = None):
    if base_dir is None:
        base_dir = txt_path.parent

    print(f"📄 플레이리스트 : {txt_path}")
    print(f"📁 세그먼트 폴더: {base_dir}")
    if key_override:
        print(f"🔑 지정 키 파일 : {key_override}")
    print(f"💾 출력 파일    : {output_path}\n")

    segments = parse_m3u8(txt_path)
    total = len(segments)
    print(f"세그먼트 {total}개 감지\n")

    key_cache = {}   # URI → key_bytes
    ok = skip = 0

    with open(output_path, "wb") as out:
        for i, seg in enumerate(segments, 1):
            seg_path = base_dir / seg["filename"]

            if not seg_path.exists():
                print(f"  ⚠️  [{i:>{len(str(total))}}/{total}] 없음: {seg['filename']}")
                skip += 1
                continue

            data = seg_path.read_bytes()

            key_info = seg["key"]
            if key_info and key_info.get("METHOD") == "AES-128":
                uri = key_info["URI"]
                if uri not in key_cache:
                    key_cache[uri] = load_key(key_info, base_dir, key_override)
                key_bytes = key_cache[uri]

                iv_str = key_info.get("IV", "")
                if iv_str:
                    iv = int(iv_str, 16).to_bytes(16, "big")
                else:
                    iv = seg["seq"].to_bytes(16, "big")

                data = decrypt_aes128(data, key_bytes, iv)
                flag = "🔓"
            else:
                flag = "✅"

            out.write(data)
            print(f"  {flag} [{i:>{len(str(total))}}/{total}] {seg['filename']}  ({len(data):,} B)")
            ok += 1

    size = output_path.stat().st_size
    print(f"\n✨ 완료  병합: {ok}개  건너뜀: {skip}개")
    print(f"   출력: {output_path}  ({size:,} bytes)")


def main():
    parser = argparse.ArgumentParser(
        description="M3U8 플레이리스트 → 로컬 세그먼트 병합",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("txt",
        help="#EXTM3U 가 담긴 .txt 파일 경로 (절대/상대 모두 가능)")
    parser.add_argument("-d", "--dir", default=None,
        help="세그먼트 파일이 있는 디렉토리\n(기본: txt 파일과 같은 폴더)")
    parser.add_argument("-k", "--key", default=None,
        help="키 파일 경로를 직접 지정\n(기본: 세그먼트 폴더에서 URI 파일명으로 자동 탐색)")
    parser.add_argument("-o", "--output", default=None,
        help="출력 파일 경로\n(기본: txt와 같은 폴더에 <txt명>.ts)")
    args = parser.parse_args()

    txt_path = Path(args.txt).resolve()
    if not txt_path.exists():
        print(f"❌ txt 파일 없음: {txt_path}")
        sys.exit(1)

    base_dir = Path(args.dir).resolve() if args.dir else txt_path.parent
    if not base_dir.is_dir():
        print(f"❌ 디렉토리 없음: {base_dir}")
        sys.exit(1)

    key_override = None
    if args.key:
        key_override = Path(args.key).resolve()
        if not key_override.exists():
            print(f"❌ 키 파일 없음: {key_override}")
            sys.exit(1)

    output_path = Path(args.output).resolve() if args.output else txt_path.with_suffix(".ts")

    try:
        merge(txt_path, output_path, base_dir, key_override)
    except FileNotFoundError as e:
        print(f"\n❌ {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()


    #클로드사랑해 ㅋ