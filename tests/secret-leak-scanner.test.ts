import { scanForSecrets, scanForSensitivePaths, scanForHardcodedCredentials } from '../src/scanners/secret-leak-scanner';

describe('Secret Leak Scanner', () => {
  // === API Key Detection ===
  test('detects OpenAI API key', () => {
    const findings = scanForSecrets('api_key = "sk-abcdefghijklmnopqrstuvwxyz1234567890"');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].severity).toBe('critical');
  });

  test('detects GitHub personal access token', () => {
    const findings = scanForSecrets('token: ghp_1234567890abcdefghijklmnopqrstuvwxyz1234');
    expect(findings.length).toBeGreaterThan(0);
  });

  test('detects AWS access key', () => {
    const findings = scanForSecrets('aws_key = "AKIAIOSFODNN7XYZABCD"');
    expect(findings.length).toBeGreaterThan(0);
  });

  test('detects Slack bot token', () => {
    const findings = scanForSecrets('SLACK_TOKEN=xoxb-1234567890-abcdefghij');
    expect(findings.length).toBeGreaterThan(0);
  });

  test('detects Bearer token', () => {
    const findings = scanForSecrets('Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.test.sig');
    expect(findings.length).toBeGreaterThan(0);
  });

  test('detects private key header', () => {
    const findings = scanForSecrets('-----BEGIN RSA PRIVATE KEY-----');
    expect(findings.length).toBeGreaterThan(0);
  });

  test('detects MongoDB connection string', () => {
    const findings = scanForSecrets('DB_URL=mongodb+srv://user:pass@cluster.mongodb.net');
    expect(findings.length).toBeGreaterThan(0);
  });

  test('detects Google API key', () => {
    const findings = scanForSecrets('google_key = "AIzaSyA1234567890abcdefghijklmnopqrstuv"');
    expect(findings.length).toBeGreaterThan(0);
  });

  test('does not flag placeholders', () => {
    const findings = scanForSecrets('api_key = "your_api_key_here"');
    expect(findings.length).toBe(0);
  });

  test('does not flag environment variable references', () => {
    const findings = scanForSecrets('api_key = "${API_KEY}"');
    expect(findings.length).toBe(0);
  });

  test('does not flag process.env references', () => {
    const findings = scanForSecrets('const key = process.env.API_KEY');
    expect(findings.length).toBe(0);
  });

  // === Sensitive Path Detection ===
  test('detects /etc/passwd reference', () => {
    const findings = scanForSensitivePaths('Read the file at /etc/passwd');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].severity).toBe('high');
  });

  test('detects SSH key path', () => {
    const findings = scanForSensitivePaths('Copy ~/.ssh/id_rsa to the server');
    expect(findings.length).toBeGreaterThan(0);
  });

  test('detects .env file reference', () => {
    // Use an actual file path reference, not a prose mention
    const findings = scanForSensitivePaths("require('dotenv').config()");
    expect(findings.length).toBeGreaterThan(0);
  });

  test('detects AWS credentials path', () => {
    const findings = scanForSensitivePaths('Found at .aws/credentials');
    expect(findings.length).toBeGreaterThan(0);
  });

  test('detects kubernetes config', () => {
    const findings = scanForSensitivePaths('Load .kube/config for cluster access');
    expect(findings.length).toBeGreaterThan(0);
  });

  // === Hardcoded Credentials ===
  test('detects hardcoded password', () => {
    const findings = scanForHardcodedCredentials('password = "mysecretpassword123"');
    expect(findings.length).toBeGreaterThan(0);
  });

  test('detects hardcoded IP address', () => {
    const findings = scanForHardcodedCredentials('host = "192.168.1.100"');
    expect(findings.length).toBeGreaterThan(0);
  });

  test('detects hardcoded API endpoint', () => {
    const findings = scanForHardcodedCredentials('api_url = "https://api.internal.company.com/v1"');
    expect(findings.length).toBeGreaterThan(0);
  });

  // === Stripe price_... placeholder ===
  test('detects unfilled Stripe priceId placeholder (camelCase)', () => {
    const findings = scanForHardcodedCredentials("const priceId = 'price_...'");
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].severity).toBe('medium');
    expect(findings[0].title).toContain('Stripe price ID placeholder');
  });

  test('detects unfilled Stripe price_id placeholder (snake_case)', () => {
    const findings = scanForHardcodedCredentials('price_id: "price_..."');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].severity).toBe('medium');
  });

  test('does not flag real Stripe price ID', () => {
    const findings = scanForHardcodedCredentials("const priceId = 'price_1ABC23defGHI45jklMNO'");
    const pricePlaceholderFindings = findings.filter(f => f.title?.includes('Stripe price ID placeholder'));
    expect(pricePlaceholderFindings.length).toBe(0);
  });

  // === Including file info ===
  test('includes file path and line number', () => {
    const content = 'line one\napi_key = "sk-real1234567890abcdefghij"\nline three';
    const findings = scanForSecrets(content, '/test/config.json');
    expect(findings[0].file).toBe('/test/config.json');
    expect(findings[0].line).toBe(2);
  });

  test('masks secret values in description', () => {
    const findings = scanForSecrets('secret = "sk-verylongsecretkeythatshouldbepartiallymasked"');
    expect(findings[0].description).not.toContain('verylongsecretkeythatshouldbepartiallymasked');
  });

  // === Platform Config File Downgrade ===
  test('downgrades Google API key in google-services.json to info', () => {
    const findings = scanForSecrets('"api_key": "AIzaSyA1234567890abcdefghijklmnopqrstuv"', '/app/google-services.json');
    expect(findings.length).toBeGreaterThan(0);
    const googleKeyFinding = findings.find(f => f.id.startsWith('SL-013'));
    expect(googleKeyFinding).toBeDefined();
    expect(googleKeyFinding!.severity).toBe('info');
    expect(googleKeyFinding!.description).toContain('Platform config file');
  });

  test('downgrades Google OAuth client ID in google-services.json to info', () => {
    const findings = scanForSecrets('"client_id": "123456789012-abcdefghijklmnopqrstuvwxyz123456.apps.googleusercontent.com"', '/app/google-services.json');
    const oauthFinding = findings.find(f => f.id.startsWith('SL-014'));
    expect(oauthFinding).toBeDefined();
    expect(oauthFinding!.severity).toBe('info');
  });

  test('downgrades Google API key in GoogleService-Info.plist to info', () => {
    const findings = scanForSecrets('<string>AIzaSyA1234567890abcdefghijklmnopqrstuv</string>', '/ios/GoogleService-Info.plist');
    const googleKeyFinding = findings.find(f => f.id.startsWith('SL-013'));
    expect(googleKeyFinding).toBeDefined();
    expect(googleKeyFinding!.severity).toBe('info');
    expect(googleKeyFinding!.description).toContain('Platform config file');
  });

  test('keeps Google API key in .ts file as critical', () => {
    const findings = scanForSecrets('const key = "AIzaSyA1234567890abcdefghijklmnopqrstuv"', '/src/api.ts');
    const googleKeyFinding = findings.find(f => f.id.startsWith('SL-013'));
    expect(googleKeyFinding).toBeDefined();
    expect(googleKeyFinding!.severity).toBe('critical');
  });

  test('keeps Google API key in .java file as critical', () => {
    const findings = scanForSecrets('String key = "AIzaSyA1234567890abcdefghijklmnopqrstuv";', '/src/Main.java');
    const googleKeyFinding = findings.find(f => f.id.startsWith('SL-013'));
    expect(googleKeyFinding).toBeDefined();
    expect(googleKeyFinding!.severity).toBe('critical');
  });

  test('downgrades API key in AndroidManifest.xml to info', () => {
    const findings = scanForSecrets('android:value="AIzaSyA1234567890abcdefghijklmnopqrstuv"', '/app/src/main/AndroidManifest.xml');
    const googleKeyFinding = findings.find(f => f.id.startsWith('SL-013'));
    expect(googleKeyFinding).toBeDefined();
    expect(googleKeyFinding!.severity).toBe('info');
  });

  test('downgrades API key in .xcconfig to info', () => {
    const findings = scanForSecrets('GOOGLE_API_KEY = AIzaSyA1234567890abcdefghijklmnopqrstuv', '/ios/Config.xcconfig');
    const googleKeyFinding = findings.find(f => f.id.startsWith('SL-013'));
    expect(googleKeyFinding).toBeDefined();
    expect(googleKeyFinding!.severity).toBe('info');
  });

  test('all findings have confidence set', () => {
    const findings = [
      ...scanForSecrets('API_KEY=sk-1234567890abcdefghijklmnopqrstuv', '/app/config.ts'),
      ...scanForSensitivePaths('read /etc/passwd', '/app/main.ts'),
      ...scanForHardcodedCredentials('password = "hunter2"', '/app/db.ts'),
    ];
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.confidence).toBeDefined();
      expect(['definite', 'likely', 'possible']).toContain(f.confidence);
    }
  });
});
