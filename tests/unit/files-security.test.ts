import { describe, it, expect } from 'vitest';
import * as path from 'path';

import { safeFilename, assertAllowedHost } from '../../src/tools/files.js';

describe('safeFilename', () => {
  it('leaves ordinary course filenames alone', () => {
    expect(safeFilename('Week 3 Notes.docx')).toBe('Week 3 Notes.docx');
    expect(safeFilename('syllabus.pdf')).toBe('syllabus.pdf');
  });

  it('strips POSIX path traversal', () => {
    expect(safeFilename('../../../etc/passwd')).toBe('passwd');
    expect(safeFilename('../../.zshrc')).toBe('zshrc');
  });

  it('strips Windows-style path traversal', () => {
    expect(safeFilename('..\\..\\evil.txt')).toBe('evil.txt');
    expect(safeFilename('C:\\Windows\\System32\\drivers\\etc\\hosts')).toBe('hosts');
  });

  it('never returns a value containing a path separator', () => {
    const hostile = [
      '../../../.ssh/authorized_keys',
      '/etc/cron.d/backdoor',
      'a/b/c.txt',
      '..\\..\\.bashrc',
    ];
    for (const name of hostile) {
      const safe = safeFilename(name);
      expect(safe).not.toContain('/');
      expect(safe).not.toContain('\\');
      expect(safe).not.toBe('..');
    }
  });

  it('refuses to produce dotfiles', () => {
    expect(safeFilename('.bashrc')).toBe('bashrc');
    expect(safeFilename('..')).toBe('download');
    expect(safeFilename('...')).toBe('download');
  });

  it('strips control characters including NUL', () => {
    expect(safeFilename('evil\x00.txt')).toBe('evil.txt');
    expect(safeFilename('re\x1fport.pdf')).toBe('report.pdf');
  });

  it('falls back when nothing usable remains', () => {
    expect(safeFilename('')).toBe('download');
    expect(safeFilename('   ')).toBe('download');
    expect(safeFilename('/', 'fallback.bin')).toBe('fallback.bin');
  });

  it('caps absurdly long names', () => {
    expect(safeFilename('a'.repeat(5000)).length).toBe(200);
  });

  it('keeps a sanitised name inside the intended directory when joined', () => {
    const dir = path.resolve('/Users/someone/Downloads');
    const joined = path.join(dir, safeFilename('../../../../tmp/pwned'));
    expect(path.dirname(joined)).toBe(dir);
  });
});

describe('assertAllowedHost', () => {
  const HOST = 'bconline.broward.edu';

  it('allows the configured D2L host', () => {
    expect(() =>
      assertAllowedHost(new URL('https://bconline.broward.edu/content/enforced/1-A/file.docx'), HOST)
    ).not.toThrow();
  });

  it('allows subdomains of the configured host', () => {
    expect(() => assertAllowedHost(new URL('https://cdn.bconline.broward.edu/f.pdf'), HOST)).not.toThrow();
  });

  it('rejects unrelated hosts', () => {
    expect(() => assertAllowedHost(new URL('https://evil.example.com/payload'), HOST)).toThrow(/only downloads from/);
  });

  it('rejects suffix-confusion lookalikes', () => {
    expect(() => assertAllowedHost(new URL('https://bconline.broward.edu.evil.com/x'), HOST)).toThrow();
    expect(() => assertAllowedHost(new URL('https://notbconline.broward.edu/x'), HOST)).toThrow();
  });

  it('rejects the K-12 district instance, which is a different institution', () => {
    expect(() => assertAllowedHost(new URL('https://broward.desire2learn.com/d2l/home'), HOST)).toThrow();
  });

  it('rejects non-https schemes', () => {
    expect(() => assertAllowedHost(new URL('http://bconline.broward.edu/f.pdf'), HOST)).toThrow(/only https/);
    expect(() => assertAllowedHost(new URL('file:///etc/passwd'), HOST)).toThrow(/only https/);
  });
});
