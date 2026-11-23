// Development/CI tool only. No application data is read or sent.
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {dirname,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {pinnedTool} from './pinned-tools.mjs';
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..'),run=promisify(execFile);
export async function main(){
  const tool=await pinnedTool('actionlint');
  // Optional Python/shell linters are deliberately separate; this checks YAML,
  // workflow schemas, action inputs and GitHub expression types consistently.
  const checked=await run(tool.path,['-no-color','-shellcheck=','-pyflakes='],{cwd:root,windowsHide:true,maxBuffer:1024*1024});
  if(checked.stdout)process.stdout.write(checked.stdout);if(checked.stderr)process.stderr.write(checked.stderr);
  process.stdout.write('workflow_schema_checks_passed\n');
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))await main();
