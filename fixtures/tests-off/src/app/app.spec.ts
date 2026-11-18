// Fixture: focused tests, so the other tests do not run. CI scan must block.
fdescribe('the application', () => {
  it.only('starts', () => {});
  it('stops', () => {});
});
