import { Buffer } from 'buffer/';
// const jksJs = require('jks-js');
const pkijs = require('pkijs');
const ans1js = require('asn1js');
import { saveAs } from 'file-saver';

export interface PEM { cert: string; key: string; };

export type JKS_MAGIC = 0xfeedfeed;
export type JKS_VERSION_1 = 0x01;
export type JKS_VERSION_2 = 0x02;
export type JKS_PRIVATE_KEY_TAG = 1;
export type JKS_TRUSTED_CERT_TAG = 2;

export const JKS_MAGIC = 0xfeedfeed;
export const JKS_VERSION_1 = 0x01;
export const JKS_VERSION_2 = 0x02;
export const JKS_PRIVATE_KEY_TAG = 1;
export const JKS_TRUSTED_CERT_TAG = 2;

export default class Jks {
  public cert!: string;
  public key!: string;
  public password!: string;
  public jks!: ArrayBuffer;

  constructor() {
  }

  /**
   * 从PEM初始化实例
   *
   * @param cert 证书PEM
   * @param key 私钥PEM
   * @param password 私钥密码，可不传
   * @returns {Jks}
   */
  static fromPEM(cert: string, key: string, password: string | null = null) {
    const jks = new Jks();
    jks.cert = cert;
    jks.key = key;
    if (password) {
      jks.password = password;
    }

    return jks;
  }


  /**
   * 从JKS初始化实例
   *
   * @param jks JavaKeyStore Buffer
   * @param password 私钥密码，可不传
   * @returns {Jks}
   */
  static fromJKS(jksContent: ArrayBuffer, password: string) {
    const jks = new Jks();
    jks.jks = jksContent;
    jks.password = password;

    return jks;
  }

  /**
   * 从jks转换为pem
   *
   * @returns {PEM}
   */
  // public getPEM(): Promise<PEM> {
  //   return new Promise(async (resolve, reject) => {
  //     if (!this.cert || !this.key) {
  //       const keystore = jksJs.toPem(
  //         this.jks,
  //         this.password
  //       );
  //       for (const alias in keystore) {
  //         if (keystore.hasOwnProperty(alias)) {
  //           const data = keystore[alias];
  //           this.cert = data.cert;
  //           this.key = data.key;
  //         }
  //       }
  //     }
  //     const cert = this.cert;
  //     const key = this.key
  //     return resolve({cert, key});
  //   });
  // }

  private dateToBuffer(date: Date): ArrayBuffer {
    // Get the timestamp from the Date object as a BigInt
    const timestamp = BigInt(date.getTime());

    // Create a 64-bit integer from the timestamp
    const timestamp64 = timestamp & BigInt("0xFFFFFFFFFFFFFFFF");

    // Convert the 64-bit integer to a hexadecimal string, padding to ensure it's 16 characters long
    const hexString = timestamp64.toString(16).padStart(16, '0');

    // Create a new ArrayBuffer to store the result
    const buffer = new ArrayBuffer(8);
    const view = new DataView(buffer);

    // Write the hexadecimal string to the ArrayBuffer in little-endian byte order
    for (let i = 0; i < 8; i++) {
      // Take two characters at a time and parse as a hexadecimal value
      const byteValue = parseInt(hexString.substr(i * 2, 2), 16);

      // Write the 8 bits to the buffer
      view.setUint8(i, byteValue);
    }

    return buffer;
  }

  /**
   * 从pem转换为jks
   *
   * @param xVersion JKS版本号，1或2，默认2
   * @param password 私钥密码，不传时从实例获取密码
   * @returns {Promise<Buffer>}
   */
  public getJKS(xVersion: JKS_VERSION_1 | JKS_VERSION_2 = JKS_VERSION_2, password: string | null = null): Promise<ArrayBuffer> {
    return new Promise(async (resolve, reject) => {
      try {
        console.log(this.cert);
        console.log(this.key);
        console.log(this.password || password);
        console.log(xVersion);
        if (!this.cert) {
          return reject(new Error('cert is required'));
        }
        if (!this.key) {
          return reject(new Error('key is required'));
        }
        if (!password && !this.password) {
          return reject(new Error('password is required'));
        }

        if (!this.jks) {
          if (!password) {
            password = this.password;
          }

          let offset = 0;

          // new class Buffer
          let buffer = Buffer.alloc(1000 * 2);
          buffer.writeUInt32BE(JKS_MAGIC, offset);

          offset += JKS_MAGIC.toString(16).length / 2;

          // parse common name in cert PEM
          const cert = this.cert;
          // first PEM block
          const pemBlock = cert.split('-----END CERTIFICATE-----')[0];
          // PEM remove header and footer and new line
          const pem = pemBlock.replace(/-----BEGIN CERTIFICATE-----/, '').replace(/-----END CERTIFICATE-----/, '').replace(/[\n\r]+/g, '');
          // base64 decode
          const pemBuffer = Buffer.from(pem, 'base64');

          // ans1js parse cert
          const asn1 = ans1js.fromBER(pemBuffer.buffer);
          const parse = new pkijs.Certificate({ schema: asn1.result });
          console.log(parse);
          // get commonName
          const commonNameTypeValue = parse.subject.typesAndValues.find(
            (typeAndValue: any) => {
              console.log(typeAndValue);
              return typeAndValue.type === '2.5.4.3'; // commonName OID
            }
          );
          console.log(commonNameTypeValue);

          let commonName = 'unknown';
          if (commonNameTypeValue && commonNameTypeValue.value && commonNameTypeValue.value.blockLength)  {
            commonName = commonNameTypeValue.value.valueBlock.value;
          }
          console.log(commonName);
          // replace commonName dot and wildcard to underline
          const alias = commonName.replace(/\.|\*/g, '_');

          buffer.writeUInt32BE(JKS_VERSION_2, offset);
          offset += 4;

          // how many cert+keypairs
          const keyCount = 1;
          buffer.writeUInt32BE(keyCount, offset);
          offset += 4;

          // tag for private key
          buffer.writeUInt32BE(JKS_PRIVATE_KEY_TAG, offset);
          offset += 4;

          // commonName length
          const aliasLength = Buffer.byteLength(alias);
          buffer.writeUInt16BE(aliasLength, offset);
          offset += 2;

          buffer.write(alias, offset, aliasLength, 'utf8');
          offset += aliasLength;

          // date, like '0x0000018c11d02835'
          // set to PEM's notBefore
          let notBefore = parse.notBefore?.value;
          if (!notBefore) {
            notBefore = new Date();
          }

          const dateBuffer = this.dateToBuffer(notBefore);
          buffer = Buffer.concat([buffer.slice(0, offset), Buffer.from(dateBuffer)]);
          offset += 8;

          const passwordBuffer = new TextEncoder().encode(password);
          // detect is private der
          const privateKey = this.key;
          // remove -----BEGIN...
          const privateKeyBlock = privateKey.replace(/-----(BEGIN|END)( (RSA|EC))? PRIVATE KEY-----/g, '').replace(/[\n\r]+/g, '');
          // base64 decode
          const privateKeyBinary = Buffer.from(privateKeyBlock, 'base64');
          const privateKeyAns1 = ans1js.fromBER(privateKeyBinary.buffer);
          // protect private key with password
          const pkcs8Simpl = new pkijs.PrivateKeyInfo({ schema: privateKeyAns1.result });
          const pkcs8 = new pkijs.PKCS8ShroudedKeyBag({ parsedValue: pkcs8Simpl });

          await pkcs8.makeInternalValues({
            password: passwordBuffer,
            iterationCount: 100000,
            hmacHashAlgorithm: 'SHA-256',
            contentEncryptionAlgorithm: <any> {
              name: "AES-CBC", // OpenSSL can handle AES-CBC only
              length: 256,
            },
          });
          const encKeyBinary = pkcs8.toSchema().toBER(false);
          // keylength to buffer
          const encKeyBuffer = Buffer.from(encKeyBinary);
          const keyLengthBuffer = new Buffer(4);
          keyLengthBuffer.writeUInt32BE(encKeyBuffer.byteLength, 0);
          buffer = Buffer.concat([buffer, keyLengthBuffer]);
          offset += 4;
          // write length to buffer
          buffer = Buffer.concat([buffer, encKeyBuffer]);
          offset += encKeyBuffer.byteLength;

          const certBuffers = this.cert.split(/-----END( (RSA|EC))? CERTIFICATE-----/g).filter(item => item && item.trim()).map((item) => {
            const pem = item.replace(/(-----BEGIN( (RSA|EC))? CERTIFICATE-----)|[\n\r]+/g, '');
            const pemBuffer = Buffer.from(pem, 'base64');
            return pemBuffer;
          });

          for (const certBuffer of certBuffers) {
            // tag for certificate
            const tagBuffer = new Buffer(4);
            tagBuffer.writeUInt32BE(JKS_TRUSTED_CERT_TAG, 0);
            buffer = Buffer.concat([buffer, tagBuffer]);
            offset += 4;

            if (xVersion === JKS_VERSION_2) {
              // certType
              const certType = 'X.509';
              const certTypeBuffer = new Buffer(4);
              certTypeBuffer.write(certType, 0, 4);
              buffer = Buffer.concat([buffer, certTypeBuffer]);
              offset += 4;
            }

            // append cert
            const certLengthBuffer = new Buffer(4);
            certLengthBuffer.writeUInt32BE(certBuffer.byteLength, 0);
            buffer = Buffer.concat([buffer, certLengthBuffer]);
            offset += 4;

            buffer = Buffer.concat([buffer, certBuffer]);
            offset += certBuffer.byteLength;
          }

          this.jks = buffer;
        }

        saveAs(new Blob([this.jks], {}), 'test.jks');
        return resolve(this.jks);
      } catch (error) {
        return reject(error);
      }
    });
  }
}
