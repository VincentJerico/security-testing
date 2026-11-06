import { test, expect } from '@playwright/test';
import { zapToSarif, stripHtml, type ZapAlert, type ZapReport } from '../scripts/zap-to-sarif.js';

/**
 * Proves the ZAP-to-SARIF conversion keeps what code scanning needs: one rule per alert, the right
 * severity, a location on the rules.conf line that gates the rule, and nothing for info alerts.
 */
const RULES_CONF = [
  '# comment line',
  '10038\tWARN\t(Content Security Policy (CSP) Header Not Set)',
  '90004\tWARN\t(Insufficient Site Isolation Against Spectre Vulnerability)',
  '10109\tIGNORE\t(Modern Web Application)',
].join('\n');

const alert = (over: Partial<ZapAlert>): ZapAlert => ({
  pluginid: '10038',
  alertRef: '10038',
  alert: 'Content Security Policy (CSP) Header Not Set',
  riskcode: '2',
  riskdesc: 'Medium (High)',
  cweid: '693',
  desc: '<p>No CSP.</p>',
  solution: '<p>Set a CSP &amp; test it.</p>',
  count: '5',
  instances: [
    { uri: 'http://juice-shop:3000/', method: 'GET' },
    { uri: 'http://juice-shop:3000/ftp', method: 'GET' },
  ],
  ...over,
});

const report = (alerts: ZapAlert[]): ZapReport => ({
  '@version': '2.17.0',
  site: [{ '@name': 'http://juice-shop:3000', alerts }],
});

test.describe('ZAP to SARIF self-test', () => {
  test('maps an alert to a rule and a result on its rules.conf line', () => {
    const sarif = zapToSarif(report([alert({})]), RULES_CONF);
    const run = sarif.runs[0]!;
    expect(run.tool.driver).toMatchObject({ name: 'OWASP ZAP', version: '2.17.0' });
    expect(run.tool.driver.rules[0]).toMatchObject({
      id: '10038',
      help: { text: 'Set a CSP & test it.' },
      properties: { tags: ['security', 'external/cwe/cwe-693'], 'security-severity': '5.0' },
    });
    expect(run.results[0]).toMatchObject({
      ruleId: '10038',
      level: 'warning',
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: 'zap/rules.conf' },
            region: { startLine: 2 },
          },
        },
      ],
    });
    expect(run.results[0]!.message.text).toBe(
      'Content Security Policy (CSP) Header Not Set (Medium (High)) on 5 URL(s): ' +
        'GET http://juice-shop:3000/; GET http://juice-shop:3000/ftp, and 3 more.',
    );
  });

  test('keeps two alerts from one plugin apart by alertRef', () => {
    const sarif = zapToSarif(
      report([
        alert({ pluginid: '90004', alertRef: '90004-2', riskcode: '1', alert: 'COEP missing' }),
        alert({ pluginid: '90004', alertRef: '90004-3', riskcode: '1', alert: 'COOP missing' }),
      ]),
      RULES_CONF,
    );
    expect(sarif.runs[0]!.results.map((r) => [r.ruleId, r.level])).toEqual([
      ['90004-2', 'note'],
      ['90004-3', 'note'],
    ]);
    expect(sarif.runs[0]!.results[0]!.locations[0]!.physicalLocation.region.startLine).toBe(3);
  });

  test('maps high risk to error and leaves informational alerts out', () => {
    const sarif = zapToSarif(
      report([
        alert({ pluginid: '10003', alertRef: '10003', riskcode: '3' }),
        alert({ pluginid: '10109', alertRef: '10109', riskcode: '0' }),
      ]),
      RULES_CONF,
    );
    expect(sarif.runs[0]!.results.map((r) => r.ruleId)).toEqual(['10003']);
    expect(sarif.runs[0]!.results[0]!.level).toBe('error');
    // 10003 isn't in this rules.conf, so the result falls back to line 1.
    expect(sarif.runs[0]!.results[0]!.locations[0]!.physicalLocation.region.startLine).toBe(1);
  });

  test('strips HTML from ZAP descriptions', () => {
    expect(stripHtml('<p>One.</p><p>Two &lt;b&gt;</p>')).toBe('One.\nTwo <b>');
  });
});
