import { Buffer } from 'buffer/';
import pkijs from 'pkijs';
import asn1js from 'asn1js';
const jksJs = require('jks-js');

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
  static fromPEM(cert: string, key: string, password: string) {
    const jks = new Jks();
    jks.cert = cert;
    jks.key = key;
    jks.password = password;

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
  public getPEM(): Promise<PEM> {
    return new Promise(async (resolve, reject) => {
      if (!this.cert || !this.key) {
        const keystore = jksJs.toPem(
          this.jks,
          this.password
        );

        for (const alias in keystore) {
          if (keystore.hasOwnProperty(alias)) {
            const data = keystore[alias];
            this.cert = data.cert;
            this.key = data.key;
          }
        }
      }
      const cert = this.cert;
      const key = this.key
      return resolve({cert, key});
    });
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

          // new class Buffer
          const buffer = Buffer.alloc(4);
          buffer.writeUInt32BE(JKS_MAGIC, 0);

          // parse common name in cert PEM
          const cert = this.cert;
          // first PEM block
          const pemBlock = cert.split('-----END CERTIFICATE-----')[0];
          // PEM remove header and footer and new line
          const pem = pemBlock.replace(/-----BEGIN CERTIFICATE-----/, '').replace(/-----END CERTIFICATE-----/, '').replace(/[\n\r]+/g, '');
          // base64 decode
          const pemBuffer = Buffer.from(pem, 'base64');

          // parse commonName from pem by asn1js
          const asn1 = asn1js.fromBER(pemBuffer.buffer);
          const certPem = new pkijs.Certificate({ schema: asn1.result });
          const commonNameTypeValue = certPem.subject.typesAndValues.find(
            (typeAndValue) => {
              console.log(typeAndValue.type);
              return typeAndValue.type === 'commonName';
            }
          );
          console.log(commonNameTypeValue);
          let commonName = 'unknown';
          if (commonNameTypeValue && commonNameTypeValue.value && commonNameTypeValue.value.blockLength)  {
            commonName = commonNameTypeValue.value.valueBlock.toString();
          }
          // replace commonName dot and wildcard to underline
          const alias = commonName.replace(/\.|\*/g, '_');

          buffer.writeUInt32BE(JKS_VERSION_2, 0);

          // how many cert+keypairs
          const keyCount = 1;
          buffer.writeUInt32BE(keyCount, 0);

          // tag for private key
          buffer.writeUInt32BE(JKS_PRIVATE_KEY_TAG, 0);

          // commonName length
          const aliasLength = Buffer.byteLength(alias);
          buffer.writeUInt16BE(aliasLength, 0);
          buffer.write(alias, 0, aliasLength, 'utf8');

          // date, like '0x0000018c11d02835'
          // set to PEM's notBefore
          let notBefore = certPem.notBefore.value;
          if (!notBefore) {
            notBefore = new Date();
          }
          // convert to hex string
          const notBeforeHex = notBefore.getTime().toString(16);
          // convert to buffer
          const notBeforeBuffer = Buffer.from(notBeforeHex, 'hex');
          // append to buffer
          buffer.writeBigUInt64BE(notBeforeBuffer.readUInt32BE(0), 0);

          // detect is private der
          const privateKey = this.key;
          // remove -----BEGIN...
          const privateKeyBlock = privateKey.replace(/-----(BEGIN|END)( (RSA|EC))? PRIVATE KEY-----/g, '').replace(/[\n\r]+/g, '');
          // base64 decode
          const privateKeyBinary = Buffer.from(privateKeyBlock, 'base64');
          // protect private key with password
          const pkcs8Simpl = new pkijs.PrivateKeyInfo({ schema: asn1js.fromBER(privateKeyBinary).result });
          const pkcs8 = new pkijs.PKCS8ShroudedKeyBag({ parsedValue: pkcs8Simpl });
          await pkcs8.makeInternalValues({
            password: new TextEncoder().encode(password),
            iterationCount: 100000,
            hmacHashAlgorithm: 'SHA-256',
            contentEncryptionAlgorithm: <any> {
              name: "AES-CBC", // OpenSSL can handle AES-CBC only
              length: 256,
            },
          });
          const encKeyBinary = pkcs8.toSchema().toBER(false);
          // to buffer
          const encKeyBuffer = Buffer.from(encKeyBinary);
          // write length to buffer
          buffer.writeUInt32BE(encKeyBuffer.byteLength, 0);
          buffer.write(encKeyBuffer.toString('binary'), 0, encKeyBuffer.byteLength, 'binary');

          const certBuffers = this.cert.split(/-----END( (RSA|EC))? CERTIFICATE-----/g).filter(item => item.trim()).map((item) => {
            const pem = item.replace(/(-----BEGIN( (RSA|EC))? CERTIFICATE-----)|[\n\r]+/g, '');
            const pemBuffer = Buffer.from(pem, 'base64');
            return pemBuffer;
          });

          for (const certBuffer of certBuffers) {
            // tag for certificate
            buffer.writeUInt32BE(JKS_TRUSTED_CERT_TAG, 0);

            if (xVersion === JKS_VERSION_2) {
              // certType
              const certType = 'X.509';
              buffer.write(certType);
            }

            // append cert
            buffer.writeUInt32BE(certBuffer.byteLength, 0);
            buffer.write(certBuffer.toString('binary'), 0, certBuffer.byteLength, 'binary');
          }

          this.jks = buffer;
        }

        return resolve(this.jks);
      } catch (error) {
        return reject(error);
      }
    });
  }
}
