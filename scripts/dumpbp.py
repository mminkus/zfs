#!/usr/bin/env python3
import argparse
import hashlib
import struct

BP_SZ = 0x80
SPA_MINBLOCKSHIFT = 9

# These track the bit widths/offsets used by include/sys/spa.h in this tree.
SPA_LSIZEBITS = 16
SPA_PSIZEBITS = 16
SPA_ASIZEBITS = 24
SPA_COMPRESSBITS = 7
SPA_VDEVBITS = 24

# Parser-side constants copied from this tree's headers.
ZIO_CHECKSUM_FUNCTIONS = 15
ZIO_COMPRESS_FUNCTIONS = 17
DMU_BSWAP_NUMFUNCS = 10
DMU_OT_NUMTYPES = 66
DMU_OT_NEWTYPE = 0x80
DMU_OT_BYTESWAP_MASK = 0x1F
SPA_MAXBLOCKSIZE = 1 << 24

ORACLE_ENC_LAYOUT = r"""
Oracle Encrypted blkptr_t (deduced, word-level)

  word 0-1 : DVA[0] data copy
  word 2-3 : DVA[1] data copy
  word 4-5 : DVA[2] repurposed for IV96
             iv96 ~= high32(word4) || word5
             word4 low32 appears reserved/unused in Oracle examples
  word 6   : blk_prop (X bit indicates encrypted/authenticated semantics)
  word 7-8 : pad
  word 9   : phys_birth
  word 10  : birth
  word 11  : fill
  word 12-15: checksum field repurposed:
              sha256_trunc160 ~= word12 || word13 || high32(word14)
              mac96           ~= low32(word14) || word15

Notes:
- This follows Oracle public docs/blog + observed mdb/zdb examples.
- It is a forensic decoder, not an authoritative crypto implementation.
"""


def u64le(buf, off):
    return struct.unpack_from("<Q", buf, off)[0]


def get_bits(word, low, nbits):
    return (word >> low) & ((1 << nbits) - 1)


def get_sb(word, low, nbits, shift, bias):
    return (get_bits(word, low, nbits) + bias) << shift


def fmt_bytes(n):
    units = ["B", "K", "M", "G", "T"]
    x = float(n)
    for u in units:
        if x < 1024.0 or u == units[-1]:
            if u == "B":
                return f"{int(x)}{u}"
            if x >= 100:
                return f"{x:.0f}{u}"
            if x >= 10:
                return f"{x:.1f}{u}"
            return f"{x:.2f}{u}"
        x /= 1024.0
    return f"{n}B"


def byte_stats(blob):
    zero = blob.count(0)
    uniq = len(set(blob))
    return {
        "len": len(blob),
        "zero": zero,
        "nonzero": len(blob) - zero,
        "unique": uniq,
    }


def parse_dva(w0, w1):
    return {
        "asize": get_sb(w0, 0, SPA_ASIZEBITS, SPA_MINBLOCKSHIFT, 0),
        "vdev": get_bits(w0, 32, SPA_VDEVBITS),
        "offset": get_sb(w1, 0, 63, SPA_MINBLOCKSHIFT, 0),
        "gang": get_bits(w1, 63, 1),
        "raw0": w0,
        "raw1": w1,
    }


def parse_prop(prop):
    return {
        "lsize": get_sb(prop, 0, SPA_LSIZEBITS, SPA_MINBLOCKSHIFT, 1),
        "psize": get_sb(prop, 16, SPA_PSIZEBITS, SPA_MINBLOCKSHIFT, 1),
        "compress": get_bits(prop, 32, SPA_COMPRESSBITS),
        "embedded": get_bits(prop, 39, 1),
        "checksum": get_bits(prop, 40, 8),
        "type": get_bits(prop, 48, 8),
        "level": get_bits(prop, 56, 5),
        "uses_crypt": get_bits(prop, 61, 1),
        "dedup": get_bits(prop, 62, 1),
        "byteorder": get_bits(prop, 63, 1),
    }


def decode_bp(bp):
    off = 0
    dvas = []
    for _ in range(3):
        w0 = u64le(bp, off)
        w1 = u64le(bp, off + 8)
        dvas.append(parse_dva(w0, w1))
        off += 16

    prop = u64le(bp, off)
    prop_dec = parse_prop(prop)
    off += 8

    pad0 = u64le(bp, off)
    pad1 = u64le(bp, off + 8)
    off += 16

    phys_birth = u64le(bp, off)
    birth = u64le(bp, off + 8)
    fill = u64le(bp, off + 16)
    off += 24

    cksum = [u64le(bp, off + 8 * i) for i in range(4)]
    cksum_bytes = bp[off:off + 32]

    iv2_openzfs = (fill >> 32) & 0xFFFFFFFF

    dva2_bytes = bp[32:48]

    return {
        "dvas": dvas,
        "prop": prop,
        "prop_dec": prop_dec,
        "pad0": pad0,
        "pad1": pad1,
        "phys_birth": phys_birth,
        "birth": birth,
        "fill": fill,
        "iv2_openzfs": iv2_openzfs,
        "cksum": cksum,
        "cksum_bytes": cksum_bytes,
        "dva2_bytes": dva2_bytes,
        "bp_sha256": hashlib.sha256(bp).hexdigest(),
        "dva2_sha256": hashlib.sha256(dva2_bytes).hexdigest(),
        "cksum_sha256": hashlib.sha256(cksum_bytes).hexdigest(),
    }


def oracle_decode(d):
    # Oracle docs/blog indicate encrypted bp IV is stored in DVA[2] and MAC
    # uses 96 bits from the checksum field.
    dva2_w0 = d["dvas"][2]["raw0"]
    dva2_w1 = d["dvas"][2]["raw1"]
    c2 = d["cksum"][2]
    c3 = d["cksum"][3]

    iv96_from_words = f"{(dva2_w0 >> 32) & 0xffffffff:08x}{dva2_w1:016x}"
    iv96_from_bytes = d["dva2_bytes"][4:16].hex()
    iv96_alt = d["dva2_bytes"][0:12].hex()

    mac96 = f"{c2 & 0xffffffff:08x}{c3:016x}"
    sha256_trunc160 = f"{d['cksum'][0]:016x}{d['cksum'][1]:016x}{(c2 >> 32) & 0xffffffff:08x}"

    data_copies = int(d["dvas"][0]["asize"] != 0) + int(d["dvas"][1]["asize"] != 0)

    return {
        "iv96_from_words": iv96_from_words,
        "iv96_from_bytes": iv96_from_bytes,
        "iv96_alt": iv96_alt,
        "dva2_low32": dva2_w0 & 0xffffffff,
        "mac96": mac96,
        "sha256_trunc160": sha256_trunc160,
        "copy_count_2dva": data_copies,
        "xbit": d["prop_dec"]["uses_crypt"],
    }


def dmu_ot_is_valid(ot):
    if ot & DMU_OT_NEWTYPE:
        return (ot & DMU_OT_BYTESWAP_MASK) < DMU_BSWAP_NUMFUNCS
    return ot < DMU_OT_NUMTYPES


def classify_plausibility(d):
    p = d["prop_dec"]
    score = 0
    total = 0
    reasons = []
    copies_all = sum(int(d["dvas"][i]["asize"] != 0) for i in range(3))
    copies_2 = sum(int(d["dvas"][i]["asize"] != 0) for i in range(2))

    total += 1
    if dmu_ot_is_valid(p["type"]):
        score += 1
    else:
        reasons.append(f"type={p['type']} invalid")

    total += 1
    if p["type"] != 0 or p["embedded"] or copies_all == 0:
        score += 1
    else:
        reasons.append("type=NONE with non-empty DVA(s)")

    total += 1
    if p["compress"] < ZIO_COMPRESS_FUNCTIONS:
        if p["compress"] not in (0, 1):
            score += 1
        else:
            reasons.append(f"compress={p['compress']} is inherit/on")
    else:
        reasons.append(f"compress={p['compress']} invalid")

    if not p["embedded"]:
        total += 1
        if p["checksum"] < ZIO_CHECKSUM_FUNCTIONS:
            if p["checksum"] not in (0, 1):
                score += 1
            else:
                reasons.append(f"checksum={p['checksum']} is inherit/on")
        else:
            reasons.append(f"checksum={p['checksum']} invalid")

    total += 1
    if 0 < p["lsize"] <= SPA_MAXBLOCKSIZE and 0 < p["psize"] <= SPA_MAXBLOCKSIZE:
        score += 1
    else:
        reasons.append(f"size out of range l={p['lsize']} p={p['psize']}")

    total += 1
    if p["psize"] <= p["lsize"] * 8 and p["lsize"] <= p["psize"] * 8:
        score += 1
    else:
        reasons.append(f"size ratio suspicious l={p['lsize']} p={p['psize']}")

    total += 1
    if not (p["embedded"] and p["uses_crypt"]):
        score += 1
    else:
        reasons.append("embedded+crypt set (mutually exclusive in OpenZFS)")

    total += 1
    if p["embedded"]:
        score += 1
    else:
        copies = copies_2 if p["uses_crypt"] else copies_all
        if copies > 0:
            score += 1
        else:
            reasons.append("no non-empty data DVAs")

    ratio = score / total if total else 0.0
    if ratio >= 0.80:
        label = "likely_plain_blkptr"
    elif ratio >= 0.70:
        label = "mixed_or_uncertain"
    else:
        label = "likely_ciphertext_or_non_blkptr"

    return {
        "score": score,
        "total": total,
        "ratio": ratio,
        "label": label,
        "reasons": reasons,
    }


def print_bp(path, idx, bp, no_decode=False, oracle_mode=False):
    d = decode_bp(bp)
    plaus = classify_plausibility(d)

    print(f"{path} BP[{idx}] @ +0x{idx * BP_SZ:03x}")

    for i, dva in enumerate(d["dvas"]):
        print(f"  DVA[{i}] raw=(0x{dva['raw0']:016x},0x{dva['raw1']:016x})")
        if not no_decode:
            if oracle_mode and i == 2:
                print("    decode        = Oracle mode: DVA[2] treated as IV carrier; "
                      "OpenZFS DVA decode suppressed")
            else:
                empty = "yes" if dva["asize"] == 0 else "no"
                print(
                    f"    decode        = vdev={dva['vdev']} off=0x{dva['offset']:x} "
                    f"asize={fmt_bytes(dva['asize'])} gang={dva['gang']} empty={empty}"
                )

    print(f"  prop raw        = 0x{d['prop']:016x}")
    if not no_decode:
        p = d["prop_dec"]
        print(
            "  prop decode     = "
            f"lsize={fmt_bytes(p['lsize'])} psize={fmt_bytes(p['psize'])} "
            f"type={p['type']} level={p['level']} cksum={p['checksum']} "
            f"comp={p['compress']} embedded={p['embedded']} crypt={p['uses_crypt']} "
            f"dedup={p['dedup']} byteorder={p['byteorder']}"
        )

    print(f"  pad             = 0x{d['pad0']:016x} 0x{d['pad1']:016x}")
    print(f"  phys_birth      = 0x{d['phys_birth']:016x}")
    print(f"  birth           = 0x{d['birth']:016x}")
    if no_decode:
        print(f"  fill            = 0x{d['fill']:016x}")
    else:
        print(f"  fill            = 0x{d['fill']:016x} (openzfs_iv2=0x{d['iv2_openzfs']:08x})")
    print(f"  cksum words     = {[f'0x{x:016x}' for x in d['cksum']]}")

    if not no_decode:
        iv_stats = byte_stats(d["dva2_bytes"])
        mac_stats = byte_stats(d["cksum_bytes"])
        print("  oracle-candidate")
        print(
            f"    iv(dva2 raw16)= {d['dva2_bytes'].hex()} "
            f"(nz={iv_stats['nonzero']}/{iv_stats['len']} uniq={iv_stats['unique']})"
        )
        print(
            f"    mac(cksum32)  = {d['cksum_bytes'].hex()} "
            f"(nz={mac_stats['nonzero']}/{mac_stats['len']} uniq={mac_stats['unique']})"
        )

    if oracle_mode:
        o = oracle_decode(d)
        print("  oracle-decode")
        print(
            f"    xbit={o['xbit']} data_copies(max2)={o['copy_count_2dva']} "
            f"dva2_low32=0x{o['dva2_low32']:08x}"
        )
        print(
            f"    iv96(word-based)   = {o['iv96_from_words']} "
            f"(high32(dva2.w0)||dva2.w1)"
        )
        print(f"    iv96(bytes[4:16])  = {o['iv96_from_bytes']}")
        print(f"    iv96(bytes[0:12])  = {o['iv96_alt']}")
        print(f"    mac96              = {o['mac96']} (low32(cksum[2])||cksum[3])")
        print(f"    sha256_trunc160    = {o['sha256_trunc160']}")

    print("  plausibility")
    print(
        f"    label={plaus['label']} score={plaus['score']}/{plaus['total']} "
        f"({plaus['ratio']:.2f})"
    )
    if plaus["reasons"]:
        print(f"    reasons            = {', '.join(plaus['reasons'])}")

    print("  fingerprints")
    print(f"    bp_sha256     = {d['bp_sha256']}")
    print(f"    dva2_sha256   = {d['dva2_sha256']}")
    print(f"    cksum_sha256  = {d['cksum_sha256']}")
    print()


def read_bps(path):
    data = open(path, "rb").read()
    n = len(data)
    if n < BP_SZ or (n % BP_SZ) != 0:
        raise SystemExit(f"{path}: size {n:#x} not multiple of 0x{BP_SZ:x}")
    out = []
    for i in range(n // BP_SZ):
        off = i * BP_SZ
        out.append(data[off:off + BP_SZ])
    return out


def compare_files(path_a, path_b):
    bps_a = read_bps(path_a)
    bps_b = read_bps(path_b)
    if len(bps_a) != len(bps_b):
        print(f"compare: bp count mismatch {path_a}={len(bps_a)} {path_b}={len(bps_b)}")
        return 1

    rc = 0
    for i, (a, b) in enumerate(zip(bps_a, bps_b)):
        da = decode_bp(a)
        db = decode_bp(b)
        same_bp = a == b
        same_dva2 = da["dva2_bytes"] == db["dva2_bytes"]
        same_cksum = da["cksum_bytes"] == db["cksum_bytes"]

        verdict = "same" if same_bp else "diff"
        print(f"BP[{i}] {verdict}: dva2={'same' if same_dva2 else 'diff'} cksum={'same' if same_cksum else 'diff'}")
        if not same_bp:
            rc = 1
            print(f"  {path_a} bp_sha256    {da['bp_sha256']}")
            print(f"  {path_b} bp_sha256    {db['bp_sha256']}")
            print(f"  {path_a} dva2_sha256  {da['dva2_sha256']}")
            print(f"  {path_b} dva2_sha256  {db['dva2_sha256']}")
            print(f"  {path_a} cksum_sha256 {da['cksum_sha256']}")
            print(f"  {path_b} cksum_sha256 {db['cksum_sha256']}")
    return rc


def main():
    ap = argparse.ArgumentParser(description="Decode blkptr_t dumps from zdb -R")
    ap.add_argument("files", nargs="+", help="raw files containing 0x80-byte blkptr records")
    ap.add_argument("--compare", action="store_true", help="compare exactly two files by BP")
    ap.add_argument("--limit", type=int, default=0, help="limit BPs printed per file (0 = all)")
    ap.add_argument("--no-decode", action="store_true",
                    help="show raw words and fingerprints only")
    ap.add_argument("--oracle", action="store_true",
                    help="print Oracle encrypted-bp interpretation (heuristic)")
    ap.add_argument("--oracle-layout", action="store_true",
                    help="print deduced Oracle encrypted blkptr layout before output")
    args = ap.parse_args()

    if args.compare:
        if len(args.files) != 2:
            raise SystemExit("--compare requires exactly two files")
        raise SystemExit(compare_files(args.files[0], args.files[1]))

    if args.oracle_layout:
        print(ORACLE_ENC_LAYOUT.strip())
        print()

    for path in args.files:
        bps = read_bps(path)
        limit = len(bps) if args.limit <= 0 else min(args.limit, len(bps))
        for idx, bp in enumerate(bps[:limit]):
            print_bp(path, idx, bp, no_decode=args.no_decode,
                     oracle_mode=args.oracle)
        if limit < len(bps):
            print(f"... ({len(bps) - limit} more BP(s) omitted; file contains {len(bps)} total)")


if __name__ == "__main__":
    main()
