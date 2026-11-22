// Developer tool only: cache stays inside the ignored workspace target directory.
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {resolve} from 'node:path';
const extension=fileURLToPath(new URL('..',import.meta.url));
const child=spawn(process.execPath,[resolve(extension,'node_modules/playwright/cli.js'),'install','--no-shell','chromium'],{
  cwd:extension,windowsHide:true,stdio:'inherit',
  env:{...process.env,PLAYWRIGHT_BROWSERS_PATH:resolve(extension,'../target/tools/playwright')},
});
child.once('error',()=>{process.stderr.write('browser_install_failed\n');process.exitCode=1;});
child.once('exit',code=>{process.exitCode=code??1;});
