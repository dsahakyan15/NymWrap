import { copyFile, mkdir, readFile, writeFile, readdir } from "node:fs/promises";
await mkdir(new URL("../dist/", import.meta.url), { recursive: true });
for (const file of ["popup.html", "popup.css"]) await copyFile(new URL(`../${file}`, import.meta.url), new URL(`../dist/${file}`, import.meta.url));
const manifest=JSON.parse(await readFile(new URL('../manifest.json',import.meta.url),'utf8'));
await mkdir(new URL('../dist-firefox/',import.meta.url),{recursive:true});
await writeFile(new URL('../dist-firefox/manifest.json',import.meta.url),JSON.stringify(manifest,null,2)+'\n');
const chrome={...manifest,background:{service_worker:'background.js',type:'module'}};delete chrome.browser_specific_settings;
await writeFile(new URL('../dist/manifest.json',import.meta.url),JSON.stringify(chrome,null,2)+'\n');
for(const file of await readdir(new URL('../dist/',import.meta.url))){if(file.endsWith('.js')||file==='popup.html'||file==='popup.css')await copyFile(new URL('../dist/'+file,import.meta.url),new URL('../dist-firefox/'+file,import.meta.url));}
