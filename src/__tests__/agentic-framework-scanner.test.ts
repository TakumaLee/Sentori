import { describe, it, expect, beforeAll, afterAll } from '@jest/globals';
import * as fs from 'fs-extra';
import * as path from 'path';
import { AgenticFrameworkScanner } from '../scanners/agentic-framework-scanner';

describe('AgenticFrameworkScanner', () => {
  const testDir = path.join(__dirname, '../../test-data/agentic-framework-scanner');
  const scanner = new AgenticFrameworkScanner();

  beforeAll(async () => {
    await fs.ensureDir(testDir);
  });

  afterAll(async () => {
    await fs.remove(testDir);
  });

  // --- AGENTIC-001: LangChain .env API key ---

  it('AGENTIC-001: should detect LANGCHAIN_API_KEY in .env (CRITICAL)', async () => {
    const testFile = path.join(testDir, '.env');
    await fs.writeFile(testFile, 'LANGCHAIN_API_KEY=lc-abcdef1234567890abcdef1234567890\nOTHER_VAR=foo\n');

    const result = await scanner.scan(testDir);
    const finding = result.findings.find(f => f.rule === 'AGENTIC-001');

    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('critical');
    expect(finding?.message).toContain('LangChain API key');
    expect(finding?.recommendation).toBeDefined();
    await fs.remove(testFile);
  });

  it('AGENTIC-001: should NOT flag LANGCHAIN_API_KEY placeholder', async () => {
    const testFile = path.join(testDir, '.env');
    await fs.writeFile(testFile, 'LANGCHAIN_API_KEY=your_key_here\n');

    const result = await scanner.scan(testDir);
    const finding = result.findings.find(f => f.rule === 'AGENTIC-001');

    expect(finding).toBeUndefined();
    await fs.remove(testFile);
  });

  it('AGENTIC-001: should downgrade severity for .env.example (INFO)', async () => {
    const testFile = path.join(testDir, '.env.example');
    await fs.writeFile(testFile, 'LANGCHAIN_API_KEY=lc-realkey1234567890abcdef\n');

    const result = await scanner.scan(testDir);
    const finding = result.findings.find(f => f.rule === 'AGENTIC-001' && f.file?.includes('.env.example'));

    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('info');
    await fs.remove(testFile);
  });

  // --- AGENTIC-002: LangChain JSON config ---

  it('AGENTIC-002: should detect api_key in langchain.json (HIGH)', async () => {
    const testFile = path.join(testDir, 'langchain.json');
    await fs.writeJson(testFile, {
      model: 'gpt-4',
      api_key: 'sk-realkey1234567890abcdef12345678',
    });

    const result = await scanner.scan(testDir);
    const finding = result.findings.find(f => f.rule === 'AGENTIC-002');

    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('high');
    expect(finding?.message).toContain('plaintext API key');
    await fs.remove(testFile);
  });

  it('AGENTIC-002: should NOT flag placeholder in langchain_config.json', async () => {
    const testFile = path.join(testDir, 'langchain_config.json');
    await fs.writeJson(testFile, {
      model: 'gpt-4',
      api_key: 'your_api_key_here',
    });

    const result = await scanner.scan(testDir);
    const finding = result.findings.find(f => f.rule === 'AGENTIC-002');

    expect(finding).toBeUndefined();
    await fs.remove(testFile);
  });

  // --- AGENTIC-003: AutoGen config ---

  it('AGENTIC-003: should detect api_key in autogen_config.json (CRITICAL)', async () => {
    const testFile = path.join(testDir, 'autogen_config.json');
    await fs.writeJson(testFile, [
      { model: 'gpt-4', api_key: 'sk-autogenrealkey1234567890abcdefghij' },
    ]);

    const result = await scanner.scan(testDir);
    const finding = result.findings.find(f => f.rule === 'AGENTIC-003');

    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('critical');
    expect(finding?.message).toContain('AutoGen config');
    await fs.remove(testFile);
  });

  it('AGENTIC-003: should detect api_key in autogen YAML config (CRITICAL)', async () => {
    const testFile = path.join(testDir, 'autogen_config.yaml');
    await fs.writeFile(testFile, 'model: gpt-4\napi_key: sk-yamlrealkey1234567890abcdef\n');

    const result = await scanner.scan(testDir);
    const finding = result.findings.find(f => f.rule === 'AGENTIC-003' && f.file?.includes('.yaml'));

    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('critical');
    await fs.remove(testFile);
  });

  it('AGENTIC-003: should detect hardcoded api_key in Python AutoGen code (CRITICAL)', async () => {
    const testFile = path.join(testDir, 'my_agent.py');
    await fs.writeFile(
      testFile,
      `import autogen

config_list = [{"model": "gpt-4", "api_key": "sk-pythonrealkey1234567890abcdef0000"}]
assistant = autogen.AssistantAgent("assistant", llm_config={"config_list": config_list})
`
    );

    const result = await scanner.scan(testDir);
    const finding = result.findings.find(f => f.rule === 'AGENTIC-003' && f.file?.includes('my_agent.py'));

    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('critical');
    expect(finding?.message).toContain('hardcoded api_key');
    await fs.remove(testFile);
  });

  it('AGENTIC-003: should NOT flag env reference in AutoGen Python', async () => {
    const testFile = path.join(testDir, 'safe_agent.py');
    await fs.writeFile(
      testFile,
      `import autogen, os

config_list = [{"model": "gpt-4", "api_key": os.environ.get("OPENAI_API_KEY")}]
`
    );

    const result = await scanner.scan(testDir);
    const finding = result.findings.find(f => f.rule === 'AGENTIC-003' && f.file?.includes('safe_agent.py'));
    expect(finding).toBeUndefined();
    await fs.remove(testFile);
  });

  // --- AGENTIC-004: CrewAI tool API keys ---

  it('AGENTIC-004: should detect tool api key in crew YAML config (HIGH)', async () => {
    const testFile = path.join(testDir, 'crew_config.yaml');
    await fs.writeFile(
      testFile,
      `agents:\n  - name: researcher\n    tools:\n      - serper_api_key: serper_realkey1234567890abcdef\n`
    );

    const result = await scanner.scan(testDir);
    const finding = result.findings.find(f => f.rule === 'AGENTIC-004');

    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('high');
    expect(finding?.message).toContain('CrewAI');
    await fs.remove(testFile);
  });

  it('AGENTIC-004: should detect hardcoded api_key in CrewAI Python (HIGH)', async () => {
    const testFile = path.join(testDir, 'crew_agents.py');
    await fs.writeFile(
      testFile,
      `from crewai import Agent
from crewai_tools import SerperDevTool

tool = SerperDevTool(api_key="serper-crewai-realkey-1234567890abc")
`
    );

    const result = await scanner.scan(testDir);
    const finding = result.findings.find(f => f.rule === 'AGENTIC-004' && f.file?.includes('crew_agents.py'));

    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('high');
    await fs.remove(testFile);
  });

  // --- AGENTIC-005: Generic hardcoded keys in agentic code ---

  it('AGENTIC-005: should detect hardcoded OPENAI_API_KEY in LangChain Python (CRITICAL)', async () => {
    const testFile = path.join(testDir, 'chain.py');
    await fs.writeFile(
      testFile,
      `from langchain.chat_models import ChatOpenAI

llm = ChatOpenAI(openai_api_key="sk-openairealkey1234567890abcdefghijklmn")
`
    );

    const result = await scanner.scan(testDir);
    const finding = result.findings.find(f => f.rule === 'AGENTIC-005' && f.file?.includes('chain.py'));

    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('critical');
    expect(finding?.message).toContain('Hardcoded');
    await fs.remove(testFile);
  });

  it('AGENTIC-005: should detect hardcoded OpenAI key in TypeScript (CRITICAL)', async () => {
    const testFile = path.join(testDir, 'agent.ts');
    await fs.writeFile(
      testFile,
      `import OpenAI from 'openai';

const client = new OpenAI({ api_key: "sk-tsrealkey1234567890abcdefghijklmn" });
`
    );

    const result = await scanner.scan(testDir);
    const finding = result.findings.find(f => f.rule === 'AGENTIC-005' && f.file?.includes('agent.ts'));

    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('critical');
    await fs.remove(testFile);
  });

  it('AGENTIC-005: should NOT flag env-var based key initialization', async () => {
    const testFile = path.join(testDir, 'safe_chain.py');
    await fs.writeFile(
      testFile,
      `from langchain.chat_models import ChatOpenAI
import os

llm = ChatOpenAI(openai_api_key=os.environ.get("OPENAI_API_KEY"))
`
    );

    const result = await scanner.scan(testDir);
    const finding = result.findings.find(f => f.rule === 'AGENTIC-005' && f.file?.includes('safe_chain.py'));
    expect(finding).toBeUndefined();
    await fs.remove(testFile);
  });

  // --- General ---

  it('should return correct scanner name and timing', async () => {
    const result = await scanner.scan(testDir);
    expect(result.scanner).toBe('AgenticFrameworkScanner');
    expect(result.duration).toBeGreaterThanOrEqual(0);
  });
});
