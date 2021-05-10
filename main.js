var g_fileContent = ArrayBuffer();

function scramble(mystr) {
	var hash = CryptoJS.MD5(mystr);
	return hash;
}

function aesEncrypt(msg, key, iv) {
	var enc = CryptoJS.AES.encrypt(msg, key, {
		iv: iv,
		mode: CryptoJS.mode.CBC,
		padding: CryptoJS.pad.Pkcs7,
	});
	var aes_out = enc.ciphertext.toString(CryptoJS.enc.Hex)
	var content = iv + aes_out;
	var _content = CryptoJS.enc.Hex.parse(content);
	var b64 = CryptoJS.enc.Base64.stringify(_content);
	return b64;
}

function shaDigest(content) {
	var _content = CryptoJS.enc.Hex.parse(content);
	var hash = CryptoJS.SHA512(content);
	return hash;
}

function arrayBufferToWordArray(ab) {
	var i8a = new Uint8Array(ab);
	var a = [];
	for (var i = 0; i < i8a.length; i += 4) {
		a.push(i8a[i] << 24 | i8a[i + 1] << 16 | i8a[i + 2] << 8 | i8a[i + 3]);
	}
	return CryptoJS.lib.WordArray.create(a, i8a.length);
}

function convertToCharser(password, specialchars) {
	let output = "";
	let k = 0;
	for (var i = 0; i < password.length; i++) {
		let c = password[i];
		if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
			output += c;
		} else {
			output += specialchars[k % specialchars.length];
			k++;
		}
	}
	return output;
}

function processValues() {
	let loginVal = document.getElementById("login").value;
	let shortPassVal = document.getElementById("shortpass").value;
	if (loginVal.length == 0 || shortPassVal.length == 0) {
		alert("Login and pass cannot be empty");
		return;
	}
	if (loginVal.length < 3) {
		alert("Login should be at least 3 characters long");
		return;
	}
	if (shortPassVal.length < 8) {
		alert("Easy password should be at least 8 characters long");
		return;
	}

	let seedFile = arrayBufferToWordArray(g_fileContent);
	if (seedFile.sigBytes == 0) {
		alert("WARNING: For the best security it is recommended to use a seed file!");
	}
	const outLen = document.getElementById("passlen").value;
	const specialChars = "_&#";

	var key = scramble(shortPassVal);
	var vec = scramble(loginVal);

	let aes_out1 = aesEncrypt(seedFile, key, vec);
	let digested = shaDigest(aes_out1);
	let outPass = digested;

	let sha_digest = CryptoJS.enc.Hex.stringify(digested);
	var passlen = (shortPassVal.length * 2) % sha_digest.length
	var key2 = sha_digest.substring(passlen, passlen + 64)

	key2 = CryptoJS.enc.Hex.parse(key2);
	let aes_out2 = aesEncrypt(aes_out1, key2, key)

	let key0 = (key.toString()).substring(0, 2);
	let start = parseInt(key0, 16) % aes_out2.length;
	let portion = aes_out2.substring(start);

	let result = CryptoJS.SHA512(portion);
	result = CryptoJS.enc.Base64.stringify(result);
	document.getElementById("longpass").value = convertToCharser(result, specialChars).substring(0, outLen);
}

function readSingleFile(e) {
	var file = e.target.files[0];
	if (!file) {
	}
	var reader = new FileReader();
	reader.onload = function (e) {
		var contents = e.target.result;
		setContents(contents);
	};
	reader.readAsArrayBuffer(file);
}

function setContents(contents) {
	g_fileContent = contents;
}

function hidePass(id, el) {
	let x = document.getElementById(id);
	if (x.type === "password") {
		x.type = "text";
		el.className = 'fa fa-eye-slash showpwd';
	} else if (x.type === "text") {
		x.type = "password";
		el.className = 'fa fa-eye showpwd';
	}
}

function toClipboard() {
	/* Get the text field */
	var passField = document.getElementById("longpass");
	if (passField.value.length == 0) {
		return;
	}
	var prevType = passField.type;
	passField.type = "text";
	/* Select the text field */
	passField.select();
	passField.setSelectionRange(0, 99999); /* For mobile devices */

	/* Copy the text inside the text field */
	var successful = document.execCommand("copy");
	passField.type = prevType;
	if (!successful) {
		alert("Failed to copy!");
	} else {
		alert("Copied!");
	}
}

function adjustLongPassField()
{
	var passLenField = document.getElementById("passlen");

	const maxLen = parseInt(passLenField.max, 10);
	const minLen = parseInt(passLenField.min, 10);
	var outLen = parseInt(passLenField.value, 10);

	if (outLen > maxLen) {
		passLenField.value = passLenField.max;
		outLen = maxLen;
	}
	if (outLen < minLen) {
		passLenField.value = passLenField.min;
		outLen = minLen;
	}
	var passField = document.getElementById("longpass");
	passField.size = outLen;
}

function initFormJS() {
	document.getElementById('file-input')
	  .addEventListener('change', readSingleFile, false);

	document.getElementById('generate')
	  .addEventListener('click', processValues, false);

	document.getElementById('copy')
	  .addEventListener('click', toClipboard, false);

	document.getElementById('passlen')
	  .addEventListener('change', adjustLongPassField, false);

	adjustLongPassField();
}
