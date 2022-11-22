const crypto = require("crypto");
const keccak256 = require("keccak256");

var publicKey = {
  pem:
    "-----BEGIN PUBLIC KEY-----\n" +
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtrgXPhu9uTXh2J5e9Vey\n" +
    "U2Nmv1om3/P/3TjGoOWVCCxrq0EnfdpuYE+VlYmMzo/ZfZ992vK4GbBdbXxcgHRk\n" +
    "J1M7Vt1cA9Zmpc4J4FCWTonVoYfBpjpa4T5Cc9BR7cKQMwa3SeVKno8W0/yL+kY1\n" +
    "9n5bDKxmuL9cliD4N3Sw0Y9ufqO0o0B4ymeJvqxGoEzFefyzSELd1nBvFWkMyJZn\n" +
    "yxLohl+bUvmGzo8GENE2vJqORF+rCr17iyzgVwBilwReqgFgpy7pZr95n0XI1X7I\n" +
    "x8ciTTmJErfTiq/fDBFn4LywEyvYgSVzkOvcknIfyvr9ynctMjGUdDVEWyLbAGpQ\n" +
    "RQIDAQAB\n" +
    "-----END PUBLIC KEY-----\n",
  algorithm: "EC_SIGN_SECP256K1_SHA256",
  pemCrc32c: { value: "41325621" },
  name: "PATH-TO-KEY-ON-KMS/cryptoKeyVersions/1",
  protectionLevel: "HSM",
};


var x509pem = publicKey.pem;
var x509der = crypto.createPublicKey(x509pem).export({ format: "der", type: "spki" });
var rawXY = x509der.subarray(-64);
console.log("Raw key: 0x" + rawXY.toString("hex"));


var hashXY = keccak256(rawXY);
var address = hashXY.subarray(-20).toString("hex").toLowerCase();


var addressHash = keccak256(address).toString("hex");
var addressChecksum = "";
for (var i = 0; i < address.length; i++) {
  if (parseInt(addressHash[i], 16) > 7) {
    addressChecksum += address[i].toUpperCase();
  } else {
    addressChecksum += address[i];
  }
}

console.log("Derived: 0x" + addressChecksum);
