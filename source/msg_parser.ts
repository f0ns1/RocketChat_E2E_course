/**
 * Messgae parser Rcocketchat crypto E2E
 * Wrapper:
 * input message Base64 encoded (IV+cipher)
 * output ciphertext on Base64 and IV on Hexadecimal
 * IGS: f0ns1.master.oscp@gmail.com
 * * */

function b64ToBuffer(base64){ return toByteArray(base64).buffer}
function toByteArray(b64){
	let tmp;
	const lens = getLens(b64);
	const validLen = lens[0];
	const placeHoldersLen = lens[1];
	const arr = new Arr(_byteLength(b64, validLen, placeHoldersLen));
	let curByte = 0;
	const len = placeHoldersLen > 0 ? validLen - 4 : validLen;
	let i;
	for (i = 0; i < len; i += 4) {
		tmp =
			(revLookup[b64.charCodeAt(i)] << 18) |
			(revLookup[b64.charCodeAt(i + 1)] << 12) |
			(revLookup[b64.charCodeAt(i + 2)] << 6) |
			revLookup[b64.charCodeAt(i + 3)];
		arr[curByte] = (tmp >> 16) & 0xff;
		curByte += 1;
		arr[curByte] = (tmp >> 8) & 0xff;
		curByte += 1;
		arr[curByte] = tmp & 0xff;
		curByte += 1;
	}

	if (placeHoldersLen === 2) {
		tmp = (revLookup[b64.charCodeAt(i)] << 2) | (revLookup[b64.charCodeAt(i + 1)] >> 4);
		arr[curByte] = tmp & 0xff;
		curByte += 1;
	}

	if (placeHoldersLen === 1) {
		tmp =
			(revLookup[b64.charCodeAt(i)] << 10) | (revLookup[b64.charCodeAt(i + 1)] << 4) | (revLookup[b64.charCodeAt(i + 2)] >> 2);
		arr[curByte] = (tmp >> 8) & 0xff;
		curByte += 1;
		arr[curByte] = tmp & 0xff;
		curByte += 1;
	}

	return arr;
};


function getLens(b64){
	const len = b64.length;
	let validLen = b64.indexOf('=');
	if (validLen === -1) {
		validLen = len;
	}
	const placeHoldersLen = validLen === len ? 0 : 4 - (validLen % 4);
	return [validLen, placeHoldersLen];
};

function byteLength(b64){
	const lens = getLens(b64);
	const validLen = lens[0];
	const placeHoldersLen = lens[1];
	return ((validLen + placeHoldersLen) * 3) / 4 - placeHoldersLen;
};

function _byteLength(b64, validLen, placeHoldersLen){
	return ((validLen + placeHoldersLen) * 3) / 4 - placeHoldersLen;
}

function splitVectorData(text){
        const vector = text.slice(0, 16);
        const data = text.slice(16);
        return [vector, data];
};

function buf2hex(buffer) {
    return [...new Uint8Array(buffer)]
        .map(x => x.toString(16).padStart(2, '0'))
        .join('');
}
 

/***
 * 
 * MAIN script
 * 
 * **/
let message ="eyJrdHkiOiJvK9MZ/310YymNwS8OOKW8al/6NSLwGByT5FYICd555JO6LdNzfe1QSHcg/bXxhmX4t0LaE3pUUvMvVREJycHX9JsDvHxo/b/7RU9Uf19ZDwhCH4ezJ32nLFLTQ87WyBACYQiFma6V8cU5CUgqlWa5NdmQ0JkMZOQemCG7lnERD5Q=";    

const lookup= [];
const revLookup= [];
const Arr = typeof Uint8Array !== 'undefined' ? Uint8Array : Array;
const code = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
for (let i = 0, len = code.length; i < len; i += 1) {
	lookup[i] = code[i];
	revLookup[code.charCodeAt(i)] = i;
}
revLookup['-'.charCodeAt(0)] = 62;
revLookup['_'.charCodeAt(0)] = 63;

let msg = b64ToBuffer(message.slice(12));
const [vector, cipherText] = splitVectorData(msg);

console.log("msg : ", msg);
console.log("vector: ", vector);
console.log("ciphertext: ", cipherText);

console.log("message : ", message);
console.log("vector: ", buf2hex(vector));
var ascii = new Uint8Array(cipherText);
var b64encoded = btoa(String.fromCharCode.apply(null, ascii));
console.log("ciphertext: ", b64encoded);

