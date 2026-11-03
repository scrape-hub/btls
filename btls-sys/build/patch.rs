//! Applies the patches to the BoringSSL source without git: unified diffs as `git diff` and
//! `diff -u` write them, applied as `git apply --whitespace=fix` does (context matched exactly,
//! else without trailing whitespace; added lines without trailing whitespace).

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

struct Hunk<'a> {
    /// The first old line, 1-based; for a hunk that removes nothing, the line it inserts after.
    old_start: usize,
    old: Vec<&'a str>,
    new: Vec<&'a str>,
}

fn invalid(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// The path of a `---`/`+++` line with `strip` leading components removed, `None` for
/// `/dev/null`.
fn file_path(line: &str, strip: usize) -> Option<PathBuf> {
    let path = line[4..].split('\t').next().unwrap_or_default().trim();
    if path == "/dev/null" {
        return None;
    }
    Some(path.split('/').skip(strip).collect())
}

/// `-a,b` or `+a,b` of a hunk header: the start and the line count (1 when left out).
fn range(text: &str) -> Option<(usize, usize)> {
    let mut parts = text[1..].splitn(2, ',');
    let start = parts.next()?.parse().ok()?;
    let count = parts.next().map_or(Some(1), |c| c.parse().ok())?;
    Some((start, count))
}

fn parse_hunk<'a>(lines: &[&'a str], at: &mut usize) -> io::Result<Hunk<'a>> {
    let header = lines[*at];
    let mut fields = header.split_whitespace().skip(1);
    let (old_start, old_count) = fields
        .next()
        .and_then(range)
        .ok_or_else(|| invalid(format!("bad hunk header: {header}")))?;
    let (_, new_count) = fields
        .next()
        .and_then(range)
        .ok_or_else(|| invalid(format!("bad hunk header: {header}")))?;
    *at += 1;
    let mut hunk = Hunk {
        old_start,
        old: Vec::new(),
        new: Vec::new(),
    };
    while hunk.old.len() < old_count || hunk.new.len() < new_count {
        let line = *lines
            .get(*at)
            .ok_or_else(|| invalid(format!("hunk cut off: {header}")))?;
        *at += 1;
        match line.chars().next() {
            // A context line whose leading space an editor dropped.
            None => {
                hunk.old.push("");
                hunk.new.push("");
            }
            Some(' ') => {
                hunk.old.push(&line[1..]);
                hunk.new.push(&line[1..]);
            }
            Some('-') => hunk.old.push(&line[1..]),
            Some('+') => hunk.new.push(line[1..].trim_end()),
            Some('\\') => {}
            Some(_) => return Err(invalid(format!("unexpected line in hunk: {line}"))),
        }
    }
    // "\ No newline at end of file" after the last line.
    if lines.get(*at).is_some_and(|line| line.starts_with('\\')) {
        *at += 1;
    }
    Ok(hunk)
}

fn matches_at(file: &[String], at: usize, old: &[&str]) -> bool {
    file.len() >= at + old.len()
        && (file[at..at + old.len()]
            .iter()
            .zip(old)
            .all(|(a, b)| a == b)
            || file[at..at + old.len()]
                .iter()
                .zip(old)
                .all(|(a, b)| a.trim_end() == b.trim_end()))
}

/// Where `hunk` applies in `file`, at or after `from`: the line it names, else the nearest match.
fn locate(file: &[String], hunk: &Hunk<'_>, from: usize, offset: isize) -> Option<usize> {
    let named = if hunk.old.is_empty() {
        hunk.old_start
    } else {
        hunk.old_start.saturating_sub(1)
    };
    let expected = named.saturating_add_signed(offset).max(from);
    let last = file.len().checked_sub(hunk.old.len())?;
    (0..=last.max(expected))
        .flat_map(|distance| {
            [
                expected.checked_add(distance),
                expected.checked_sub(distance),
            ]
        })
        .flatten()
        .filter(|&at| at >= from && at <= last)
        .find(|&at| matches_at(file, at, &hunk.old))
}

fn patch_file(path: &Path, hunks: &[Hunk<'_>]) -> io::Result<()> {
    let text = fs::read_to_string(path)
        .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", path.display())))?;
    let eol = if text.contains("\r\n") { "\r\n" } else { "\n" };
    let final_newline = text.ends_with('\n');
    let mut file: Vec<String> = text
        .lines()
        .map(|line| line.strip_suffix('\r').unwrap_or(line).to_string())
        .collect();
    let mut from = 0;
    let mut offset: isize = 0;
    for hunk in hunks {
        let at = locate(&file, hunk, from, offset).ok_or_else(|| {
            invalid(format!(
                "{}: hunk at line {} does not apply",
                path.display(),
                hunk.old_start
            ))
        })?;
        let new: Vec<String> = hunk.new.iter().map(|line| (*line).to_string()).collect();
        file.splice(at..at + hunk.old.len(), new);
        from = at + hunk.new.len();
        let named = if hunk.old.is_empty() {
            hunk.old_start
        } else {
            hunk.old_start.saturating_sub(1)
        };
        offset = at as isize - named as isize + hunk.new.len() as isize - hunk.old.len() as isize;
    }
    let mut out = file.join(eol);
    if final_newline || text.is_empty() {
        out.push_str(eol);
    }
    fs::write(path, out)
}

/// Applies `patch` to the tree at `root`, with `strip` leading path components removed from its
/// file names (`git apply -p`).
pub fn apply(root: &Path, patch: &str, strip: usize) -> io::Result<()> {
    let lines: Vec<&str> = patch
        .lines()
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
        .collect();
    let mut at = 0;
    let mut files = 0;
    while at < lines.len() {
        if !(lines[at].starts_with("--- ")
            && lines
                .get(at + 1)
                .is_some_and(|line| line.starts_with("+++ ")))
        {
            at += 1;
            continue;
        }
        let old = file_path(lines[at], strip);
        let new = file_path(lines[at + 1], strip);
        at += 2;
        let mut hunks = Vec::new();
        while lines.get(at).is_some_and(|line| line.starts_with("@@ ")) {
            hunks.push(parse_hunk(&lines, &mut at)?);
        }
        match (old, new) {
            (Some(_), Some(path)) => patch_file(&root.join(path), &hunks)?,
            (None, Some(path)) => {
                let path = root.join(path);
                if let Some(dir) = path.parent() {
                    fs::create_dir_all(dir)?;
                }
                let lines: Vec<&str> = hunks.iter().flat_map(|hunk| hunk.new.clone()).collect();
                fs::write(path, lines.join("\n") + "\n")?;
            }
            (Some(path), None) => fs::remove_file(root.join(path))?,
            (None, None) => return Err(invalid("a diff of /dev/null to /dev/null".into())),
        }
        files += 1;
    }
    if files == 0 {
        return Err(invalid("no file diff in the patch".into()));
    }
    Ok(())
}
