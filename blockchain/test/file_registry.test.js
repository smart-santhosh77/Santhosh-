const FileRegistry = artifacts.require("FileRegistry");

contract("FileRegistry", (accounts) => {
  let registry;

  beforeEach(async () => {
    registry = await FileRegistry.new();
  });

  it("records the ciphertext digest and reporter", async () => {
    const digest = `0x${"ab".repeat(32)}`;
    const transaction = await registry.recordHash(digest, "demo-file-id", { from: accounts[1] });
    const proof = await registry.proofs(digest);

    assert.equal(proof.reporter, accounts[1]);
    assert.equal(proof.timestamp.toString(), transaction.logs[0].args.timestamp.toString());
    assert.equal(transaction.logs[0].args.fileId, "demo-file-id");
  });

  it("rejects empty digests", async () => {
    try {
      await registry.recordHash(`0x${"00".repeat(32)}`, "demo-file-id");
      assert.fail("expected zero digest to revert");
    } catch (error) {
      assert.include(error.message, "empty digest");
    }
  });
});
