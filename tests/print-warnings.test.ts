import { printConfigWarnings } from '../src/utils/print-warnings';

describe('printConfigWarnings', () => {
  test('calls console.warn for each warning plus a trailing blank line', () => {
    const spy = jest.spyOn(console, 'warn').mockImplementation(() => {});
    printConfigWarnings(['warning A', 'warning B']);
    expect(spy).toHaveBeenCalledTimes(3); // 2 warnings + blank line
    expect(spy.mock.calls[0][0]).toContain('warning A');
    expect(spy.mock.calls[1][0]).toContain('warning B');
    expect(spy.mock.calls[2][0]).toBe('');
    spy.mockRestore();
  });

  test('includes the ⚠ indicator in each warning line', () => {
    const spy = jest.spyOn(console, 'warn').mockImplementation(() => {});
    printConfigWarnings(['test warning']);
    expect(spy.mock.calls[0][0]).toContain('⚠');
    spy.mockRestore();
  });

  test('emits only the blank line when the list is empty', () => {
    const spy = jest.spyOn(console, 'warn').mockImplementation(() => {});
    printConfigWarnings([]);
    expect(spy).toHaveBeenCalledTimes(1);
    expect(spy.mock.calls[0][0]).toBe('');
    spy.mockRestore();
  });
});
