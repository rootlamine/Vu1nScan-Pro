import { spawn } from 'child_process';
import * as path from 'path';
import { ModuleOutput } from '@/domain/types';

// Résolution du chemin absolu vers le dossier scanner Python
const SCANNER_DIR = path.resolve(__dirname, '..', '..', '..', 'scanner');

/**
 * Lance un module Python et retourne son output JSON.
 * Timeout : 120s. Erreurs stderr loggées mais non bloquantes.
 */
export function runModule(
  slug: string,
  url: string,
  depth: string,
  timeout = 120,
): Promise<ModuleOutput> {
  return new Promise((resolve) => {
    const scriptPath = path.join(SCANNER_DIR, 'modules', `${slug}.py`);
    const args = ['--url', url, '--depth', depth, '--timeout', String(timeout)];

    let stdout = '';
    let stderr = '';
    let timedOut = false;

    // Utilise le Python du venv si disponible (défini dans .env comme PYTHON_BIN)
    const pythonBin = process.env.PYTHON_BIN
      ? path.resolve(SCANNER_DIR, process.env.PYTHON_BIN.replace('../scanner/', ''))
      : 'python3';

    const child = spawn(pythonBin, [scriptPath, ...args], {
      cwd:  path.join(SCANNER_DIR, 'modules'),
      env:  { ...process.env, PYTHONPATH: SCANNER_DIR },
    });

    // Tuer le process après timeout
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGTERM');
      resolve({
        module:          slug,
        status:          'error',
        duration_ms:     timeout * 1000,
        error:           `Timeout après ${timeout}s`,
        vulnerabilities: [],
      });
    }, timeout * 1000);

    child.stdout.on('data', (chunk: Buffer) => { stdout += chunk.toString(); });
    child.stderr.on('data', (chunk: Buffer) => { stderr += chunk.toString(); });

    child.on('error', (err) => {
      clearTimeout(timer);
      if (timedOut) return;
      resolve({
        module:          slug,
        status:          'error',
        duration_ms:     0,
        error:           `Impossible de lancer python3 : ${err.message}`,
        vulnerabilities: [],
      });
    });

    child.on('close', (code) => {
      clearTimeout(timer);
      if (timedOut) return;

      if (stderr) console.error(`[Scanner:${slug}] stderr:`, stderr.slice(0, 300));

      // Extraire le JSON du stdout (ignorer les warnings Python éventuels)
      const jsonStart = stdout.indexOf('{');
      const jsonEnd   = stdout.lastIndexOf('}');
      if (jsonStart === -1 || jsonEnd === -1) {
        resolve({
          module:          slug,
          status:          'error',
          duration_ms:     0,
          error:           `Sortie non-JSON (code ${code}): ${stdout.slice(0, 200)}`,
          vulnerabilities: [],
        });
        return;
      }

      try {
        const parsed = JSON.parse(stdout.slice(jsonStart, jsonEnd + 1)) as ModuleOutput;
        resolve(parsed);
      } catch (e) {
        resolve({
          module:          slug,
          status:          'error',
          duration_ms:     0,
          error:           `Erreur parsing JSON : ${(e as Error).message}`,
          vulnerabilities: [],
        });
      }
    });
  });
}

/**
 * Lance tous les modules en parallèle et retourne les résultats settled.
 */
export async function runAll(
  slugs: string[],
  url: string,
  depth: string,
): Promise<PromiseSettledResult<ModuleOutput>[]> {
  return Promise.allSettled(slugs.map(slug => runModule(slug, url, depth)));
}
