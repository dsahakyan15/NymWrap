// Deterministic code-native application mark; writes an uncompressed Windows ICO.
import {mkdir,writeFile} from "node:fs/promises";
import {deflateSync} from "node:zlib";
const size=64;
const pixels=Buffer.alloc(size*size*4);
for(let y=0;y<size;y++)for(let x=0;x<size;x++){
  const inside=(x-32)**2+(y-32)**2<29**2;
  const n=(x>=18&&x<=23&&y>=23&&y<=46)||(x>=37&&x<=42&&y>=23&&y<=46)||(y>=23&&y<=28&&x>=21&&x<=39);
  const arrow=(x>=33&&x<=47&&y>=14&&y<=18)||(x>=43&&x<=47&&y>=14&&y<=29)||(x>=31&&x<=45&&Math.abs(y-(59-x))<=2);
  const i=(y*size+x)*4;const c=n||arrow?[220,237,186]:[45,74,53];pixels.set([...c,inside?255:0],i);
}
function crc32(buffer){let crc=0xffffffff;for(const byte of buffer){crc^=byte;for(let i=0;i<8;i++)crc=(crc>>>1)^((crc&1)?0xedb88320:0);}return (crc^0xffffffff)>>>0;}
function chunk(name,data){const type=Buffer.from(name);const out=Buffer.alloc(data.length+12);out.writeUInt32BE(data.length);type.copy(out,4);data.copy(out,8);out.writeUInt32BE(crc32(Buffer.concat([type,data])),8+data.length);return out;}
const header=Buffer.alloc(13);header.writeUInt32BE(size,0);header.writeUInt32BE(size,4);header[8]=8;header[9]=6;
const scanlines=Buffer.alloc((size*4+1)*size);for(let y=0;y<size;y++)pixels.copy(scanlines,y*(size*4+1)+1,y*size*4,(y+1)*size*4);
const png=Buffer.concat([Buffer.from([137,80,78,71,13,10,26,10]),chunk("IHDR",header),chunk("IDAT",deflateSync(scanlines)),chunk("IEND",Buffer.alloc(0))]);
const icoHeader=Buffer.alloc(22);icoHeader.writeUInt16LE(1,2);icoHeader.writeUInt16LE(1,4);icoHeader[6]=size;icoHeader[7]=size;icoHeader.writeUInt16LE(1,10);icoHeader.writeUInt16LE(32,12);icoHeader.writeUInt32LE(png.length,14);icoHeader.writeUInt32LE(22,18);
const folder=new URL("../src-tauri/icons/",import.meta.url);await mkdir(folder,{recursive:true});await writeFile(new URL("icon.png",folder),png);await writeFile(new URL("icon.ico",folder),Buffer.concat([icoHeader,png]));
