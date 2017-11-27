'use strict';

const Fs = require('fs');

const Code = require('code');
const Lab = require('lab');

const Native = require('../lib');


// Fixtures
const cert = Fs.readFileSync('./test/fixtures/cert.pem');
const key = Fs.readFileSync('./test/fixtures/key.pem');


// Set-up lab
const lab = exports.lab = Lab.script();
const describe = lab.describe;
const it = lab.it;
const expect = Code.expect;

describe('crypto', () => {

    it('should generate a keyPair object', () => {

        const result = Native.createKeyPair();
        expect(result).to.be.an.object();
        expect(result.privateKey).to.be.a.string();
        expect(result.publicKey).to.be.a.string();

    });


    it('should generate a keyPair object async', async () => {

        const result = await Native.createKeyPairAsync();
        expect(result).to.be.an.object();

    });

    it('should throw an error if createCSR is called with no arguments', () => {

        expect(() => {

            Native.createCSR();
        }).to.throw(Error);
    });

    it('should throw an error if createCSR is called without an object as argument', () => {

        expect(() => {

            Native.createCSR('Hello World\0');
        }).to.throw(Error);
    });

    it('should call createCSR with correct arguments and return a buffer of signing request', () => {

        const params = {
            certificate: cert,
            privateKey: key,
            passphrase: 'test',
            options: {
                commonName: '*.acme.com',
                orgName: 'Acme',
                orgUnit: 'IT',
                city: 'Hollywood',
                state: 'California',
                country: 'US'
            }
        };

        const result = Native.createCSR(params);
        expect(result).to.be.a.buffer();

    });

    it('should thrown an error due to invalid cert parameter', () => {

        expect(() => {

            Native.getFingerprint(null);
        }).to.throw(Error);
    });

    it('should thrown an error due to invalid digest type', () => {

        expect(() => {

            Native.getFingerprint(cert, 'invalid');
        }).to.throw(Error);
    });


    it('should return a fingerprint string of X509/pem certificate', () => {

        const md5 = Native.getFingerprint(cert, 'md5');
        const sha1 = Native.getFingerprint(cert);
        const sha256 = Native.getFingerprint(cert, 'sha256');
        const sha512 = Native.getFingerprint(cert, 'sha512');
        expect(md5).to.be.a.string().and.equal('D5:58:CE:14:0F:13:07:DD:1F:38:62:9C:22:B9:B2:D2');
        expect(sha1).to.be.a.string().and.equal('2A:F0:C1:19:CE:8B:87:DA:33:5E:FA:14:B6:41:91:8D:5B:36:D9:48');
        expect(sha256).to.be.a.string().and.equal('68:AD:52:1E:B0:75:3A:E8:24:B2:0E:37:DC:4E:DB:29:43:94:1C:75:CF:F8:E4:97:D1:18:65:48:B8:89:09:B2');
        expect(sha512).to.be.a.string().and.equal('B1:36:8B:38:79:CE:2B:EE:DE:1B:2E:25:5E:BA:61:C7:75:CB:C3:2B:5F:1F:EC:B4:31:95:F1:1A:80:C0:D3:7D:B1:9D:1A:71:61:C1:20:6E:01:F4:27:58:DF:FA:16:D9:32:17:74:9C:79:0A:FD:49:DB:D7:07:1C:12:60:74:D0');
    });

});
