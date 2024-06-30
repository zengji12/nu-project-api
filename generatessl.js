const forge = require('node-forge');
const fs = require('fs');

// Generate a key pair
const pki = forge.pki;
const keys = pki.rsa.generateKeyPair(2048);
const privateKey = pki.privateKeyToPem(keys.privateKey);
const publicKey = pki.publicKeyToPem(keys.publicKey);

// Create a self-signed certificate
const cert = pki.createCertificate();
cert.publicKey = keys.publicKey;
cert.serialNumber = '01';
cert.validity.notBefore = new Date();
cert.validity.notAfter = new Date();
cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);

const attrs = [{
  name: 'commonName',
  value: 'localhost'
}, {
  name: 'countryName',
  value: 'ID'
}, {
  shortName: 'ST',
  value: 'Jawa Barat'
}, {
  name: 'localityName',
  value: 'Bogor'
}, {
  name: 'organizationName',
  value: 'Poltek SSN'
}, {
  shortName: 'OU',
  value: 'Independent Corps'
}];

cert.setSubject(attrs);
cert.setIssuer(attrs);
cert.sign(keys.privateKey);

// PEM-format keys and cert
const pemCert = pki.certificateToPem(cert);

// Save the keys and certificate to files
fs.writeFileSync('private.key', privateKey);
fs.writeFileSync('public.key', publicKey);
fs.writeFileSync('certificate.crt', pemCert);

console.log('Certificates generated successfully');
