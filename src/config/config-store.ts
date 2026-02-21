// This module manages encrypted runtime configuration lifecycle and in-memory unlock state.

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { SqliteStore } from '../db/database.js';
import type { EncryptedConfig, RuntimeConfig, SetupPayload } from '../types/domain.js';
import { AppError } from '../utils/errors.js';
import {
  createPassphraseVerifier,
  decryptSecret,
  decryptRuntimeConfig,
  encryptSecret,
  encryptRuntimeConfig
} from './crypto.js';

export interface ConfigStoreOptions {
  configPath: string;
  db: SqliteStore;
}

// This class encapsulates setup, unlock, and secure runtime access for encrypted secrets.
export class ConfigStore {
  private readonly configPath: string;
  private readonly db: SqliteStore;
  private runtimeConfig: RuntimeConfig | null = null;
  private activePassphrase: string | null = null;

  public constructor(options: ConfigStoreOptions) {
    this.configPath = options.configPath;
    this.db = options.db;

    if (!existsSync(dirname(this.configPath))) {
      mkdirSync(dirname(this.configPath), { recursive: true });
    }
  }

  // This method indicates whether encrypted configuration already exists.
  public isInitialized(): boolean {
    return existsSync(this.configPath) && this.db.getAdminVerifier() !== null;
  }

  // This method indicates whether runtime config is currently decrypted in memory.
  public isUnlocked(): boolean {
    return this.runtimeConfig !== null;
  }

  // This method initializes encrypted runtime config and stores admin passphrase verifier.
  public initialize(payload: SetupPayload): void {
    if (this.isInitialized()) {
      throw new AppError(409, 'already_initialized', 'Server setup has already been completed.');
    }

    const config: RuntimeConfig = {
      requestTimeoutMs: payload.requestTimeoutMs ?? 10_000,
      maxRetries: payload.maxRetries ?? 3,
      retryBaseDelayMs: payload.retryBaseDelayMs ?? 350,
      planTtlHours: payload.planTtlHours ?? 24,
      // This default keeps OAuth client sessions unbounded until admins choose a finite policy.
      oauthSessionLifetime: payload.oauthSessionLifetime ?? 'permanent',
      oauthClientId: payload.oauthClientId?.trim() ? payload.oauthClientId.trim() : undefined,
      oauthClientSecret: payload.oauthClientSecret?.trim() ? payload.oauthClientSecret.trim() : undefined
    };

    const encrypted = encryptRuntimeConfig(config, payload.masterPassphrase);
    writeFileSync(this.configPath, JSON.stringify(encrypted, null, 2), {
      encoding: 'utf8',
      mode: 0o600
    });

    const verifier = createPassphraseVerifier(payload.masterPassphrase);
    this.db.setAdminVerifier(verifier);
    this.db.setStateBool('setup_completed', true);

    this.runtimeConfig = config;
    this.activePassphrase = payload.masterPassphrase;
  }

  // This method unlocks encrypted config after restart using the master passphrase.
  public unlock(passphrase: string): void {
    if (!this.isInitialized()) {
      throw new AppError(400, 'not_initialized', 'Server has not been initialized yet.');
    }

    if (!existsSync(this.configPath)) {
      throw new AppError(500, 'missing_config_file', 'Encrypted config file is missing.');
    }

    const content = readFileSync(this.configPath, 'utf8');
    const encrypted = JSON.parse(content) as EncryptedConfig;
    this.runtimeConfig = decryptRuntimeConfig(encrypted, passphrase);
    this.activePassphrase = passphrase;
  }

  // This method rotates runtime config and re-encrypts using the active in-memory passphrase.
  public updateConfig(updater: (current: RuntimeConfig) => RuntimeConfig): void {
    if (!this.activePassphrase) {
      throw new AppError(503, 'config_locked', 'Runtime secrets are locked. Unlock required.');
    }

    const current = this.getRuntimeConfig();
    const next = updater(current);
    const encrypted = encryptRuntimeConfig(next, this.activePassphrase);
    writeFileSync(this.configPath, JSON.stringify(encrypted, null, 2), {
      encoding: 'utf8',
      mode: 0o600
    });
    this.runtimeConfig = next;
  }

  // This method returns decrypted runtime config or raises a controlled lock error.
  public getRuntimeConfig(): RuntimeConfig {
    if (!this.runtimeConfig) {
      throw new AppError(503, 'config_locked', 'Runtime secrets are locked. Unlock required.');
    }

    return this.runtimeConfig;
  }

  // This method encrypts arbitrary secret strings with the active master passphrase.
  public encryptSecret(value: string): EncryptedConfig {
    if (!this.activePassphrase) {
      throw new AppError(503, 'config_locked', 'Runtime secrets are locked. Unlock required.');
    }

    return encryptSecret(value, this.activePassphrase);
  }

  // This method decrypts arbitrary secret strings with the active master passphrase.
  public decryptSecret(payload: EncryptedConfig): string {
    if (!this.activePassphrase) {
      throw new AppError(503, 'config_locked', 'Runtime secrets are locked. Unlock required.');
    }

    return decryptSecret(payload, this.activePassphrase);
  }
}
