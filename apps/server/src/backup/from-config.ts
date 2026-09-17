import type { Config } from '../config.js';
import { createS3Store, type ObjectStore } from './store.js';

/** The offsite store the configuration describes, or undefined when none is configured. */
export function offsiteStore(config: Pick<Config, 'BACKUP_S3_BUCKET' | 'BACKUP_S3_REGION' | 'BACKUP_KMS_KEY_ID' | 'BACKUP_S3_ENDPOINT'>): ObjectStore | undefined {
  if (!config.BACKUP_S3_BUCKET || !config.BACKUP_KMS_KEY_ID) return undefined;
  return createS3Store({
    bucket: config.BACKUP_S3_BUCKET,
    region: config.BACKUP_S3_REGION,
    kmsKeyId: config.BACKUP_KMS_KEY_ID,
    endpoint: config.BACKUP_S3_ENDPOINT,
  });
}
