import { readFileSync } from 'node:fs';
import { styleText } from 'node:util';

import { generateVapidKeys } from './index.js';

/** Where the CLI writes, and whether it may use colour. Injectable for tests. */
export type CliIo = {
  out: (text: string) => void;
  err: (text: string) => void;
  /** True when stdout is a terminal and NO_COLOR is unset. */
  color: boolean;
};

/**
 * Whether to use colour: only in a terminal, and never when NO_COLOR is set to anything.
 *
 * @param isTTY - Whether stdout is a terminal.
 * @param env - The environment to read NO_COLOR from.
 * @returns True if output may be coloured.
 */
export function shouldUseColor(isTTY: boolean | undefined, env: NodeJS.ProcessEnv): boolean {
  return Boolean(isTTY) && !env.NO_COLOR;
}

type Style = Parameters<typeof styleText>[0];

/** The package version, read from package.json next to dist/ (or src/ in tests). */
function version(): string {
  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
  return String(pkg.version);
}

function help(paint: (style: Style, text: string) => string): string {
  return [
    `${paint('bold', 'tiny-web-push')} ${paint('dim', `v${version()}`)}`,
    '',
    paint('bold', 'Usage'),
    '  tiny-web-push <command>',
    '',
    paint('bold', 'Commands'),
    '  keys           Print a new VAPID key pair',
    '',
    paint('bold', 'Options'),
    '  -h, --help     Show this help',
    '  -v, --version  Show the version',
    '',
    paint('bold', 'Examples'),
    '  npx tiny-web-push keys',
    '  npx tiny-web-push keys >> .env',
    '',
  ].join('\n');
}

/**
 * Runs the CLI and returns its exit code: 0 on success, 2 for a usage error.
 *
 * @param args - The arguments after the program name, like `['keys']`.
 * @param io - Where to write, and whether to use colour.
 * @returns The process exit code.
 */
export function runCli(args: readonly string[], io: CliIo): number {
  const paint = (style: Style, text: string) => (io.color ? styleText(style, text) : text);
  const [command, ...rest] = args;

  if (command === undefined || command === '-h' || command === '--help' || command === 'help') {
    io.out(help(paint));
    return 0;
  }
  if (command === '-v' || command === '--version') {
    io.out(`${version()}\n`);
    return 0;
  }
  if (command === 'keys' && rest.length === 0) {
    const { publicKey, privateKey } = generateVapidKeys();
    // Plain KEY=value lines, so the output can go straight into a .env file.
    io.out(`VAPID_PUBLIC_KEY=${publicKey}\nVAPID_PRIVATE_KEY=${privateKey}\n`);
    if (io.color) {
      io.err(
        `${paint('dim', 'The public key goes to the browser. Keep the private key secret.')}\n`
      );
    }
    return 0;
  }

  const what = command === 'keys' ? `unexpected argument "${rest[0]}"` : `unknown command "${command}"`;
  io.err(`${paint('red', 'Error:')} ${what}\nRun "tiny-web-push --help" for usage.\n`);
  return 2;
}
