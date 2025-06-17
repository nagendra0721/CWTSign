package io.mosip.cwtsign.service.impl;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPrivateKeySpec;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.NamedParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.AbstractMap.SimpleEntry;
import java.util.Base64;
import java.util.Date;
import java.util.HexFormat;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;

import com.authlete.cbor.*;
import com.authlete.cose.*;
import io.mosip.cwtsign.dto.CWTSignRequestDto;
import io.mosip.cwtsign.dto.CWTSignResponseDto;
import io.mosip.cwtsign.dto.CWTVerifyRequestDto;
import io.mosip.cwtsign.dto.CWTVerifyResponseDto;
import io.mosip.cwtsign.service.CWTSignService;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.json.JSONObject;

import com.authlete.cose.constants.COSEAlgorithms;
import com.authlete.cwt.CWT;
import com.authlete.cwt.CWTClaimsSet;
import com.authlete.cwt.CWTClaimsSetBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class CWTSignServiceImpl implements CWTSignService {

    private static final int CLAIM_169 = 169;
    private static final String ISS = "www.mosip.io";
    private static final String ED25519_KEY_ALIAS = "ed25519-cwtsign";
    private static final String JWK_FILE_NAME = "key.jwk";

    @Value("${mosip.cwt.sign.p12.file.path:./cwt-keystore.p12}")
    String p12FilePath;
  
    String keystorePassword = "1234";

    private KeyStore keyStore;
    private Provider provider = setupProvider();
    private String keyStoreType = "PKCS12";

    @PostConstruct
    public void init() {
        System.out.println("Initializing CWT Sign Service with Ed25519 key management");
        Security.addProvider(provider);
        initKeystore();
        ensureEd25519KeyExists();
    }

    private void initKeystore() {
        try {
            keyStore = KeyStore.getInstance(keyStoreType);
            Path path = Paths.get(p12FilePath);

            if (!Files.exists(path)) {
                log.info("Creating new keystore: {}", p12FilePath);
                keyStore.load(null, keystorePassword.toCharArray());
            } else {
                try (InputStream p12FileStream = new FileInputStream(p12FilePath)) {
                    log.info("Loading existing keystore: {}", p12FilePath);
                    keyStore.load(p12FileStream, keystorePassword.toCharArray());
                }
            }
        } catch (Exception e) {
            log.error("Error while loading or creating keystore.", e);
            throw new RuntimeException("Error while loading keystore.", e);
        }
    }

    private void ensureEd25519KeyExists() {
        try {
            if (!keyStore.containsAlias(ED25519_KEY_ALIAS)) {
                log.info("Ed25519 key not found, generating from JWK file.");
                generateEd25519KeyFromJWKFile();
                saveKeystore();
            } else {
                log.info("Ed25519 key found in keystore, using existing key with alias: {}", ED25519_KEY_ALIAS);
            }
        } catch (Exception e) {
            log.error("Error ensuring Ed25519 key exists.{}", e.getMessage());
            throw new RuntimeException("Error ensuring Ed25519 key exists", e);
        }
    }

    private JSONObject loadJWKFromFile() throws Exception {
        InputStream inputStream = CWTSignServiceImpl.class.getClassLoader().getResourceAsStream(JWK_FILE_NAME);
        String keyContent = "";
        log.info("Loading JWK file: {}", JWK_FILE_NAME);

        if (Objects.nonNull(inputStream)) {
            keyContent = new String(inputStream.readAllBytes());
            inputStream.close();
        } else {
            Path keyFilePath = Path.of("../resources/" + JWK_FILE_NAME);
            if (Files.exists(keyFilePath)) {
                keyContent = Files.readString(keyFilePath);
            } else {
                throw new Exception("JWK file not found: " + JWK_FILE_NAME);
            }
        }

        if (keyContent.length() == 0) {
            throw new Exception("JWK file is empty: " + JWK_FILE_NAME);
        }

        return new JSONObject(keyContent);
    }

    private void generateEd25519KeyFromJWKFile() throws Exception {
        log.info("Generating Ed25519 key from JWK file");
        JSONObject jwk = loadJWKFromFile();

        // Extract private key
        String dValue = jwk.getString("d");
        byte[] privateKeyBytes = Base64.getUrlDecoder().decode(dValue);

        KeyFactory keyFactory = KeyFactory.getInstance("Ed25519");
        EdECPrivateKeySpec privateKeySpec = new EdECPrivateKeySpec(NamedParameterSpec.ED25519, privateKeyBytes);
        EdECPrivateKey privateKey = (EdECPrivateKey) keyFactory.generatePrivate(privateKeySpec);

        // Extract public key
        String xValue = jwk.getString("x");
        byte[] publicKeyBytes = Base64.getUrlDecoder().decode(xValue);

        // Convert X coordinate to EdECPoint
        int keyLen = publicKeyBytes.length;
        boolean xBit = (publicKeyBytes[keyLen - 1] & 0x80) != 0;
        publicKeyBytes[keyLen - 1] = (byte)(publicKeyBytes[keyLen - 1] & 0x7f);

        byte[] publicKeyBytesBE = new byte[keyLen];
        for(int i = 0; i < keyLen; i++) {
            publicKeyBytesBE[i] = publicKeyBytes[keyLen - 1 - i];
        }

        BigInteger publicKeyY = new BigInteger(1, publicKeyBytesBE);
        EdECPublicKeySpec publicKeySpec = new EdECPublicKeySpec(NamedParameterSpec.ED25519,
                new EdECPoint(xBit, publicKeyY));
        EdECPublicKey publicKey = (EdECPublicKey) keyFactory.generatePublic(publicKeySpec);

        // Create self-signed certificate
        java.security.cert.Certificate certificate = createSelfSignedCertificate(privateKey, publicKey, jwk.getString("kid"));

        // Store in keystore
        java.security.cert.Certificate[] certificateChain = { certificate };
        keyStore.setKeyEntry(ED25519_KEY_ALIAS, privateKey, keystorePassword.toCharArray(), certificateChain);

        System.out.println("Generated and stored Ed25519 key with alias: " + ED25519_KEY_ALIAS + " from JWK file");
    }

    private java.security.cert.Certificate createSelfSignedCertificate(PrivateKey privateKey, PublicKey publicKey, String keyId) throws Exception {
        // Create self-signed certificate using BouncyCastle
        log.info("Creating self-signed certificate for Ed25519 key");
        long now = System.currentTimeMillis();
        Date startDate = new Date(now);
        Date endDate = new Date(now + (365L * 24 * 60 * 60 * 1000)); // 1 year validity

        X500Name dnName = new org.bouncycastle.asn1.x500.X500Name(
                "CN=CWT Signing Key (" + keyId + "), O=MOSIP, C=IN");
        BigInteger certSerialNumber = new BigInteger(Long.toString(now));

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                dnName, certSerialNumber, startDate, endDate, dnName, publicKey);

        ContentSigner contentSigner = new JcaContentSignerBuilder("Ed25519")
                .setProvider(provider).build(privateKey);

        X509CertificateHolder certHolder = certBuilder.build(contentSigner);
        return new JcaX509CertificateConverter()
                .setProvider(provider).getCertificate(certHolder);
    }

    private void saveKeystore() throws Exception {
        try (FileOutputStream fos = new FileOutputStream(p12FilePath)) {
            keyStore.store(fos, keystorePassword.toCharArray());
            log.info("Keystore saved to: {}", p12FilePath);
        }
    }

    private Provider setupProvider() {
        log.info("Setting up BouncyCastle provider");
        return new BouncyCastleProvider();
    }

    private Entry<String, EdECPrivateKey> getEd25519PrivateKey() {
        log.info("Retrieving Ed25519 private key with alias: {}", ED25519_KEY_ALIAS);
        try {
            EdECPrivateKey privateKey = (EdECPrivateKey) keyStore.getKey(ED25519_KEY_ALIAS, keystorePassword.toCharArray());
            if (privateKey == null) {
                throw new RuntimeException("Ed25519 private key not found with alias: " + ED25519_KEY_ALIAS);
            }
            return new SimpleEntry<>(ED25519_KEY_ALIAS, privateKey);
        } catch (Exception e) {
            log.error("Error retrieving Ed25519 private key: {}", e.getMessage());
            throw new RuntimeException("Error retrieving Ed25519 private key", e);
        }
    }

    private Entry<String, EdECPublicKey> getEd25519PublicKey() {
        log.info("Retrieving Ed25519 public key with alias: {}", ED25519_KEY_ALIAS);
        try {
            java.security.cert.Certificate certificate = keyStore.getCertificate(ED25519_KEY_ALIAS);
            if (certificate == null) {
                throw new RuntimeException("Ed25519 certificate not found with alias: " + ED25519_KEY_ALIAS);
            }
            EdECPublicKey publicKey = (EdECPublicKey) certificate.getPublicKey();
            return new SimpleEntry<>(ED25519_KEY_ALIAS, publicKey);
        } catch (Exception e) {
            log.error("Error retrieving Ed25519 public key: {}", e.getMessage());
            throw new RuntimeException("Error retrieving Ed25519 public key", e);
        }
    }

    @Override
    public CWTSignResponseDto cwtSign(CWTSignRequestDto requestDto) {
        log.info("CWT Signing for claim 169 data{}", requestDto.getClaim169Data());
        String claim169Data = requestDto.getClaim169Data();

        log.info("getting Ed25519 key pair for signing");
        Entry<String, EdECPrivateKey> keyPair = getEd25519PrivateKey();
        int algorithm = COSEAlgorithms.EdDSA;

        COSEProtectedHeader protectedHeader = new COSEProtectedHeaderBuilder().alg(algorithm).build();
        COSEUnprotectedHeader unprotectedHeader = new COSEUnprotectedHeaderBuilder().kid(keyPair.getKey()).build();

        long currentTime = Instant.now().getEpochSecond();
        long expireTime = Instant.ofEpochSecond(currentTime).plus(365, ChronoUnit.DAYS).getEpochSecond();

        try {
            byte[] claim169Bytes = HexFormat.of().parseHex(claim169Data);
            CBORItem item = new CBORDecoder(claim169Bytes).next();
            CBORPairList pairList = (CBORPairList) item;
            Map<Object, Object> claim169Map = pairList.parse();

            processPhotoData(claim169Map);

            CBORPairList updatedPairList = (CBORPairList) new CBORizer().cborizeMap(claim169Map);
            byte[] claim169Bts = updatedPairList.encode();

            CWTClaimsSet claimsSet = new CWTClaimsSetBuilder()
                    .iss(ISS)
                    .exp(expireTime)
                    .nbf(currentTime)
                    .iat(currentTime)
                    .put(CLAIM_169, claim169Bts)
                    .build();

            CBORByteArray claim169Payload = new CBORByteArray(claimsSet.encode());

            log.debug("CWT Signing: claim169Payload and header");
            SigStructure sigStructure = new SigStructureBuilder().signature1()
                    .bodyAttributes(protectedHeader)
                    .payload(claim169Payload)
                    .build();

            COSESigner signer = new COSESigner(keyPair.getValue());
            byte[] signature = signer.sign(sigStructure, algorithm);

            COSESign1 sign1 = new COSESign1Builder()
                    .protectedHeader(protectedHeader)
                    .unprotectedHeader(unprotectedHeader)
                    .payload(claim169Payload)
                    .signature(signature)
                    .build();

            CWT cwt = new CWT(sign1);

            log.info("CWT Signed Successfully...");
            CWTSignResponseDto responseDto = new CWTSignResponseDto();
            responseDto.setSuccess(true);
            responseDto.setMessage("CWT Signed Successfully with Ed25519 from JWK file");
            responseDto.setCwtHexData(cwt.encodeToHex());
            return responseDto;
        } catch (Exception e) {
            System.out.println("Error during CWT signing: " + e.getMessage());
            throw new RuntimeException("Error during CWT signing", e);
        }
    }

    private void processPhotoData(Map<Object, Object> claim169Map) {
        for (Object key : claim169Map.keySet()) {
            if (((Integer) key) == 62) {
                Map<Object, Object> photoDataMap = (Map) claim169Map.get(key);
                String photoData = (String) photoDataMap.get(Integer.valueOf(0));
                byte[] photoBytes = HexFormat.of().parseHex(photoData);
                photoDataMap.put(0, photoBytes);
                claim169Map.put(62, photoDataMap);
                break;
            }
        }
    }

    @Override
    public CWTVerifyResponseDto cwtVerify(CWTVerifyRequestDto requestDto) {
        log.info("CWT Verification for claim 169 data {}", requestDto.getCwtSignedData());
        try {
            String cwtSignedData = requestDto.getCwtSignedData();
            log.info("getting Ed25519 key pair for verification");
            Entry<String, EdECPublicKey> publicKeyPair = getEd25519PublicKey();

            COSEVerifier verifier = new COSEVerifier(publicKeyPair.getValue());

            byte[] encodedCWT = HexFormat.of().parseHex(cwtSignedData);
            CWT cwt = (CWT) new CBORDecoder(encodedCWT).next();
            COSEMessage message = cwt.getMessage();

            COSESign1 sign1 = (COSESign1) message;
            boolean valid = verifier.verify(sign1);

            log.info("CWT Verified Successfully...");
            CWTVerifyResponseDto responseDto = new CWTVerifyResponseDto();
            responseDto.setSuccess(true);
            responseDto.setMessage("CWT Verified Successfully with Ed25519 from JWK file");
            responseDto.setValid(valid);
            responseDto.setStatus(valid ? "Valid" : "Invalid");
            return responseDto;
        } catch (Exception e) {
            System.out.println("Error during CWT verification: " + e.getMessage());
            throw new RuntimeException("Error during CWT verification", e);

        }
    }
}
