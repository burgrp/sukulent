const fs = require("fs");
const pro = require("util").promisify;
const prettifyXml = require("prettify-xml");
const url = require("url");
const uuidv4 = require("uuid/v4");
const DOMParser = require("xmldom").DOMParser;
const xmlCrypto = require("xml-crypto");

async function load(file) {
	try {
		return await pro(fs.readFile)(file, "utf8");
	} catch (e) {
		throw `Chyba čtení souboru ${file}. ${e.message}`;
	}
}

function extractCerts(cert) {
	let result = [];
	let acc;
	cert.split("\n").forEach(line => {
		if (line === "-----BEGIN CERTIFICATE-----") {
			acc = "";
		} else {
			if (line === "-----END CERTIFICATE-----") {
				result.push(acc);
				acc = undefined;
			} else if (acc !== undefined) {
				acc += line;
			}
		}
	});
	return result;
}

function removeEmptyTexts(parent) {
	let remove = [];
	for (let i = 0; i < parent.childNodes.length; i++) {
		let el = parent.childNodes[i];
		if (el.nodeType === 3 && !el.data.trim()) {
			remove.push(el);
		}
		if (el.nodeType === 1) {
			removeEmptyTexts(el);
		}
	}
	remove.forEach(el => parent.removeChild(el));
}

function signRequest(request, certPem) {

	let doc = new DOMParser().parseFromString(request);
	removeEmptyTexts(doc.documentElement);

	let suklNs = "http://www.sukl.cz/erp/201704";

	let message = doc.createElementNS(suklNs, "Zprava");
	function addToMessage(elName, value) {
		let el = doc.createElement(elName);
		let txt = doc.createTextNode(value);
		el.appendChild(txt);
		message.appendChild(el);
	}
	addToMessage("ID_Zpravy", uuidv4());
	addToMessage("Verze", "201704A");
	addToMessage("Odeslano", new Date().toJSON());
	addToMessage("SW_Klienta", "Sukulent0000");

	let root = doc.documentElement;
	root.appendChild(message);

	request = root.toString();

	let sig = new xmlCrypto.SignedXml(false);

	let extractedCerts = extractCerts(certPem);

	sig.addReference("/*", ["http://www.w3.org/2000/09/xmldsig#enveloped-signature"], "http://www.w3.org/2001/04/xmlenc#sha256");
	sig.signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
	sig.references[0].isEmptyUri = true;
	sig.signingKey = certPem;
	sig.keyInfoProvider = {
		getKeyInfo(signingKey, prefix) {
			return `<X509Data><X509SubjectName>A subject...</X509SubjectName>${extractedCerts.map(c => "<X509Certificate>" + c + "</X509Certificate>").join("")}</X509Data>`;
		}
	};
	sig.computeSignature(request);
	request = sig.getSignedXml();

	request = `<?xml version="1.0" encoding="UTF-8"?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Header/><soapenv:Body>${request}</soapenv:Body></soapenv:Envelope>`;

	return request;
}

async function sendRequest(request) {
	
}

async function start() {

	let request = await load("request.xml");
	let certPerson = await load("cert-person.pem");
	let certSuklPem = await load("cert-sukl.pem");
	let authUsername = await load("auth-username.txt");
	let authPassword = await load("auth-password.txt");

	let signedRequest = signRequest(request, certPerson);
	
	console.info(sendRequest(signRequest));
}

start().catch(console.error);


