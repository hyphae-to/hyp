import assert from "node:assert/strict";
import { test } from "node:test";
import { claudeProjectDir, cutTranscriptAfter, moveTranscriptCwd, transcriptCwd } from "./claudeTranscript.ts";

const transcript = [
  JSON.stringify({ type: "summary", summary: "x" }),
  JSON.stringify({ type: "user", cwd: "/Users/b/Workspace/repo", message: { content: "path /Users/b/Workspace/repo/a" } }),
  JSON.stringify({ type: "assistant", cwd: "/Users/b/Workspace/repo/sub", uuid: "1" }),
  JSON.stringify({ type: "user", cwd: "/Users/b/Workspace/repo-other" }),
  "not json",
  "",
].join("\n");

test("claudeProjectDir matches Claude's directory naming", () => {
  assert.equal(claudeProjectDir("/home/bogdan/.t3/worktrees/x_y"), "-home-bogdan--t3-worktrees-x-y");
});

test("transcriptCwd returns the first recorded cwd", () => {
  assert.equal(transcriptCwd(transcript), "/Users/b/Workspace/repo");
  assert.equal(transcriptCwd("garbage\n{}\n"), undefined);
});

test("moveTranscriptCwd moves cwd at and under the root only, keeping everything else", () => {
  const { text, moved } = moveTranscriptCwd(transcript, "/Users/b/Workspace/repo", "/home/b/repo");
  assert.equal(moved, 2);
  const lines = text.split("\n");
  assert.equal(lines.length, 6);
  assert.equal(lines[0], JSON.stringify({ type: "summary", summary: "x" }));
  assert.deepEqual(JSON.parse(lines[1] ?? ""), {
    type: "user",
    cwd: "/home/b/repo",
    message: { content: "path /Users/b/Workspace/repo/a" },
  });
  assert.deepEqual(JSON.parse(lines[2] ?? ""), { type: "assistant", cwd: "/home/b/repo/sub", uuid: "1" });
  assert.equal(lines[3], JSON.stringify({ type: "user", cwd: "/Users/b/Workspace/repo-other" }));
  assert.equal(lines[4], "not json");
  assert.equal(lines[5], "");
});

test("cutTranscriptAfter keeps records up to the completed turn's last message", () => {
  const lines = [
    JSON.stringify({ type: "user", uuid: "u1" }),
    JSON.stringify({ type: "assistant", uuid: "a1" }),
    JSON.stringify({ type: "user", uuid: "u2" }),
    JSON.stringify({ type: "assistant", uuid: "a2", message: { content: [{ type: "tool_use" }] } }),
  ];
  assert.equal(cutTranscriptAfter(lines.join("\n"), "a1"), `${lines.slice(0, 2).join("\n")}\n`);
  assert.equal(cutTranscriptAfter(lines.join("\n"), "missing"), null);
});
