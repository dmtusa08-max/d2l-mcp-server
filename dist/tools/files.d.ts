/**
 * This tool exists to pull course files out of D2L, so a request aimed anywhere
 * else is either a mistake or an instruction injected into course content that
 * the model has been talked into following. Refuse it rather than fetching it.
 */
export declare function assertAllowedHost(target: URL, allowedHost?: string): void;
/**
 * Reduce an attacker-influenced name to a single harmless path segment.
 * The name can come from a remote Content-Disposition header or from the URL,
 * so it must never be able to steer the write out of the target directory.
 */
export declare function safeFilename(raw: string, fallback?: string): string;
export declare function downloadFile(url: string, savePath?: string): Promise<{
    path: string;
    filename: string;
    size: number;
    contentType: string;
    content: string | null;
}>;
