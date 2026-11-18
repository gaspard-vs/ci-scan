describe('a suite', () => {
  // ruleid: tests-off-focus
  fit('runs alone', () => {});

  // ok: tests-off-focus
  it('runs with the others', () => {});

  // ok: tests-off-focus
  xit('is skipped, but does not stop the others', () => {});
});

// ruleid: tests-off-focus
fdescribe('a focused suite', () => {});

// ruleid: tests-off-focus
describe.only('a focused suite', () => {});

// ruleid: tests-off-focus
it.only('a focused test', () => {});

// ruleid: tests-off-focus
test.only('a focused test', () => {});

// ruleid: tests-off-focus
test.describe.only('a focused Playwright suite', () => {});

// ok: tests-off-focus
const layout = { fit: (size: number) => size };
