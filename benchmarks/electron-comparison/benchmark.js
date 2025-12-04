#!/usr/bin/env node
/**
 * @file benchmark.js
 * @brief Benchmark comparison: turbo-asar vs @electron/asar
 *
 */

const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');
const chalk = require('chalk');
const Table = require('cli-table3');

// Configuration
const WARMUP_RUNS = 2;
const BENCHMARK_RUNS = 5;
const BASE_DIR = path.resolve(__dirname, 'tmp');
const TEST_DIR = path.join(BASE_DIR, 'bench_data');
const ELECTRON_ARCHIVE = path.join(BASE_DIR, 'electron_bench.asar');
const TURBO_ARCHIVE = path.join(BASE_DIR, 'turbo_bench.asar');
const EXTRACT_DIR = path.join(BASE_DIR, 'bench_extract');

// Test configurations
const TEST_CONFIGS = [
    { name: 'Small (10 files, ~50KB)', dirs: 2, filesPerDir: 5, fileSize: 5 * 1024 },
    { name: 'Medium (100 files, ~10MB)', dirs: 10, filesPerDir: 10, fileSize: 100 * 1024 },
    { name: 'Large (1000 files, ~100MB)', dirs: 100, filesPerDir: 10, fileSize: 100 * 1024 },
];

// Find turbo-asar binary
function findTurboAsar() {
    const possiblePaths = [
        '../../build/turbo-asar',
        '../../cmake-build-release-visual-studio/turbo-asar.exe',
        '../../cmake-build-release-mingw/turbo-asar.exe',
    ];

    for (const p of possiblePaths) {
        const fullPath = path.resolve(__dirname, p);
        if (fs.existsSync(fullPath)) return fullPath;
    }

    // Try to find in PATH
    try {
        const ret = spawnSync('which', ['turbo-asar'], { encoding: 'utf8' });
        if (ret.status === 0) return 'turbo-asar';
    } catch {
        return null;
    }
    return null;
}

// Get robust command for @electron/asar
function getElectronAsarConfig() {
    try {
        const pkgPath = require.resolve('@electron/asar/package.json');
        const pkg = require(pkgPath);
        const binRelative = typeof pkg.bin === 'object' ? pkg.bin.asar : pkg.bin;
        const binPath = path.join(path.dirname(pkgPath), binRelative);
        return { cmd: process.execPath, args: [binPath] };
    } catch (e) {
        console.warn(chalk.yellow('⚠️  Could not resolve @electron/asar path. Falling back to npx.'));
        return { cmd: 'npx', args: ['asar'] };
    }
}

// Helper to run commands safely
function safeExec(command, args, options = {}) {
    const ret = spawnSync(command, args, { ...options, stdio: 'pipe' });
    if (ret.error) throw new Error(`Failed to spawn '${command}': ${ret.error.message}`);
    if (ret.status !== 0) {
        const stderr = ret.stderr ? ret.stderr.toString() : 'Unknown error';
        throw new Error(`Command failed (Exit ${ret.status}):\n${stderr}`);
    }
    return ret;
}

// Generate random data
function generateRandomData(size) {
    const buffer = Buffer.alloc(size);
    for (let i = 0; i < size; i++) {
        buffer[i] = Math.floor(Math.random() * 256);
    }
    return buffer;
}

// Create test data
function createTestData(config) {
    process.stdout.write(chalk.dim(`   Generating data for ${config.name}... `));

    if (fs.existsSync(TEST_DIR)) fs.rmSync(TEST_DIR, { recursive: true, force: true });
    fs.mkdirSync(TEST_DIR, { recursive: true });

    let totalFiles = 0;
    let totalSize = 0;

    for (let d = 0; d < config.dirs; d++) {
        const dirPath = path.join(TEST_DIR, `dir${d.toString().padStart(3, '0')}`);
        fs.mkdirSync(dirPath, { recursive: true });
        for (let f = 0; f < config.filesPerDir; f++) {
            const filePath = path.join(dirPath, `file${f.toString().padStart(2, '0')}.dat`);
            fs.writeFileSync(filePath, generateRandomData(config.fileSize));
            totalFiles++;
            totalSize += config.fileSize;
        }
    }
    console.log(chalk.green('Done'));
    return { totalFiles, totalSize };
}

// Cleanup
function cleanup() {
    const toRemove = [TEST_DIR, ELECTRON_ARCHIVE, TURBO_ARCHIVE, EXTRACT_DIR];
    for (const p of toRemove) {
        if (fs.existsSync(p)) {
            try {
                if (fs.statSync(p).isDirectory()) fs.rmSync(p, { recursive: true, force: true });
                else fs.unlinkSync(p);
            } catch {}
        }
    }
}

// Timer
function hrtime() {
    const [sec, nsec] = process.hrtime();
    return sec * 1000 + nsec / 1e6;
}

// Benchmark runner
function runBenchmark(name, fn, runs = BENCHMARK_RUNS, warmup = WARMUP_RUNS) {
    // Warmup
    for (let i = 0; i < warmup; i++) {
        try { fn(); } catch (e) {
            console.error(chalk.red(`\n❌ Error during warmup for '${name}': ${e.message}`));
            process.exit(1);
        }
    }
    // Benchmark
    const times = [];
    for (let i = 0; i < runs; i++) {
        const start = hrtime();
        fn();
        times.push(hrtime() - start);
    }
    times.sort((a, b) => a - b);
    return {
        avg: times.reduce((a, b) => a + b, 0) / times.length,
    };
}

// Benchmark Wrappers
function benchmarkElectronPack(config) {
    if (fs.existsSync(ELECTRON_ARCHIVE)) fs.unlinkSync(ELECTRON_ARCHIVE);
    safeExec(config.cmd, [...config.args, 'pack', TEST_DIR, ELECTRON_ARCHIVE]);
}
function benchmarkTurboPack(binPath) {
    if (fs.existsSync(TURBO_ARCHIVE)) fs.unlinkSync(TURBO_ARCHIVE);
    safeExec(binPath, ['pack', TEST_DIR, TURBO_ARCHIVE]);
}
function benchmarkElectronExtract(config) {
    if (fs.existsSync(EXTRACT_DIR)) fs.rmSync(EXTRACT_DIR, { recursive: true, force: true });
    safeExec(config.cmd, [...config.args, 'extract', ELECTRON_ARCHIVE, EXTRACT_DIR]);
}
function benchmarkTurboExtract(binPath) {
    if (fs.existsSync(EXTRACT_DIR)) fs.rmSync(EXTRACT_DIR, { recursive: true, force: true });
    safeExec(binPath, ['extract', TURBO_ARCHIVE, EXTRACT_DIR]);
}
function benchmarkElectronList(config) {
    return safeExec(config.cmd, [...config.args, 'list', ELECTRON_ARCHIVE]).stdout;
}
function benchmarkTurboList(binPath) {
    return safeExec(binPath, ['list', TURBO_ARCHIVE]).stdout;
}

// Format helpers
function formatTime(ms) {
    if (ms < 1) return `${(ms * 1000).toFixed(2)} µs`;
    if (ms < 1000) return `${ms.toFixed(2)} ms`;
    return `${(ms / 1000).toFixed(2)} s`;
}

function speedup(baseline, optimized) {
    return baseline / optimized;
}

function printResults(results) {
    console.log('\n' + chalk.bold.cyan('🏁 BENCHMARK RESULTS'));

    for (const config of results) {
        const table = new Table({
            head: [
                chalk.white('Operation'),
                chalk.blue('@electron/asar'),
                chalk.magenta('turbo-asar'),
                chalk.yellow('Speedup')
            ],
            style: { head: [], border: [] },
            colWidths: [15, 20, 20, 25]
        });

        console.log(`\n📦 ${chalk.bold(config.name)}`);
        console.log(chalk.dim(`   Files: ${config.totalFiles} | Size: ${(config.totalSize / 1024 / 1024).toFixed(2)} MB`));

        for (const op of ['pack', 'extract', 'list']) {
            const electron = config[op].electron;
            const turbo = config[op].turbo;
            const sp = speedup(electron.avg, turbo.avg);

            let spStr;
            if (sp >= 1.1) spStr = chalk.green(`✔ ${sp.toFixed(1)}x faster`);
            else if (sp <= 0.9) spStr = chalk.red(`✘ ${(1/sp).toFixed(1)}x slower`);
            else spStr = chalk.gray(`≈ equivalent`);

            table.push([
                chalk.bold(op),
                formatTime(electron.avg),
                formatTime(turbo.avg),
                spStr
            ]);
        }
        console.log(table.toString());
    }
    console.log();
}

async function main() {
    console.clear();
    console.log(chalk.bgBlue.white.bold(' 🚀 TURBO-ASAR BENCHMARK '));
    console.log(chalk.dim(' =======================\n'));

    const turboAsarPath = findTurboAsar();
    if (!turboAsarPath) {
        console.error(chalk.red('❌ turbo-asar binary not found.'));
        process.exit(1);
    }
    console.log(`✅ turbo-asar:   ${chalk.cyan(turboAsarPath)}`);

    const electronConfig = getElectronAsarConfig();
    console.log(`✅ @electron/asar: ${chalk.blue(electronConfig.args[0])}`);

    console.log(`\n📊 Running ${chalk.yellow(BENCHMARK_RUNS)} runs (+${WARMUP_RUNS} warmup)`);

    if (!fs.existsSync(BASE_DIR)) fs.mkdirSync(BASE_DIR, { recursive: true });

    const results = [];

    for (const config of TEST_CONFIGS) {
        const { totalFiles, totalSize } = createTestData(config);
        const result = {
            name: config.name,
            totalFiles,
            totalSize,
            pack: {}, extract: {}, list: {}
        };

        const steps = [
            { key: 'pack', label: 'Pack', eFn: () => benchmarkElectronPack(electronConfig), tFn: () => benchmarkTurboPack(turboAsarPath) },
            { key: 'extract', label: 'Extract', eFn: () => benchmarkElectronExtract(electronConfig), tFn: () => benchmarkTurboExtract(turboAsarPath) },
            { key: 'list', label: 'List', eFn: () => benchmarkElectronList(electronConfig), tFn: () => benchmarkTurboList(turboAsarPath) }
        ];

        for (const step of steps) {
            process.stdout.write(`   Running ${step.label.padEnd(10)} ... `);
            result[step.key].electron = runBenchmark(step.key, step.eFn);
            result[step.key].turbo = runBenchmark(step.key, step.tFn);
            console.log(chalk.green('Done'));
        }
        results.push(result);
    }

    printResults(results);
    cleanup();
}

main().catch(err => {
    console.error(chalk.red('Fatal Error:'), err);
    cleanup();
    process.exit(1);
});