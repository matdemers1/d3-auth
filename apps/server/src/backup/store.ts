import { createReadStream, createWriteStream } from 'node:fs';
import { copyFile, mkdir, readdir, stat } from 'node:fs/promises';
import { dirname, join, relative } from 'node:path';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { GetObjectCommand, ListObjectsV2Command, PutObjectCommand, S3Client } from '@aws-sdk/client-s3';

// Where bundles go (ADR-004). An adapter, like mail: S3 with SSE-KMS in production, a directory in
// tests and for an operator who wants a copy on a disk they can carry.

export interface StoredObject {
  key: string;
  size: number;
  modified: Date;
}

export interface ObjectStore {
  readonly describe: string;
  put(key: string, file: string): Promise<void>;
  get(key: string, file: string): Promise<void>;
  /** Newest first. */
  list(prefix: string): Promise<StoredObject[]>;
}

export interface S3StoreOptions {
  bucket: string;
  region: string;
  /** Key id or alias. Every object is written under it; the bucket default is not relied on. */
  kmsKeyId: string;
  /** For S3-compatible stores in tests; unset in production. */
  endpoint?: string | undefined;
}

export function createS3Store({ bucket, region, kmsKeyId, endpoint }: S3StoreOptions): ObjectStore {
  // Credentials come from the standard AWS environment variables, and only ever from there.
  const s3 = new S3Client({ region, ...(endpoint ? { endpoint, forcePathStyle: true } : {}) });
  return {
    describe: `s3://${bucket}`,
    async put(key, file) {
      const { size } = await stat(file);
      await s3.send(
        new PutObjectCommand({
          Bucket: bucket,
          Key: key,
          Body: createReadStream(file),
          ContentLength: size,
          ContentType: 'application/gzip',
          ServerSideEncryption: 'aws:kms',
          SSEKMSKeyId: kmsKeyId,
          BucketKeyEnabled: true,
        }),
      );
    },
    async get(key, file) {
      const answer = await s3.send(new GetObjectCommand({ Bucket: bucket, Key: key }));
      if (!(answer.Body instanceof Readable)) throw new Error(`s3://${bucket}/${key} has no body`);
      await pipeline(answer.Body, createWriteStream(file));
    },
    async list(prefix) {
      const found: StoredObject[] = [];
      let token: string | undefined;
      do {
        const page = await s3.send(new ListObjectsV2Command({ Bucket: bucket, Prefix: prefix, ContinuationToken: token }));
        for (const entry of page.Contents ?? []) {
          if (entry.Key) found.push({ key: entry.Key, size: entry.Size ?? 0, modified: entry.LastModified ?? new Date(0) });
        }
        token = page.IsTruncated ? page.NextContinuationToken : undefined;
      } while (token);
      return found.sort((a, b) => b.key.localeCompare(a.key));
    },
  };
}

export function createDirectoryStore(root: string): ObjectStore {
  const walk = async (dir: string): Promise<string[]> => {
    const entries = await readdir(dir, { withFileTypes: true }).catch(() => []);
    const nested = await Promise.all(entries.map((entry) => (entry.isDirectory() ? walk(join(dir, entry.name)) : Promise.resolve([join(dir, entry.name)]))));
    return nested.flat();
  };
  return {
    describe: root,
    async put(key, file) {
      const target = join(root, key);
      await mkdir(dirname(target), { recursive: true });
      await copyFile(file, target);
    },
    async get(key, file) {
      await copyFile(join(root, key), file);
    },
    async list(prefix) {
      const files = await walk(root);
      const found = await Promise.all(
        files
          .map((path) => ({ path, key: relative(root, path).split('\\').join('/') }))
          .filter((entry) => entry.key.startsWith(prefix))
          .map(async (entry) => {
            const info = await stat(entry.path);
            return { key: entry.key, size: info.size, modified: info.mtime };
          }),
      );
      return found.sort((a, b) => b.key.localeCompare(a.key));
    },
  };
}
