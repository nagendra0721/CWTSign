package io.mosip.cwtsign.service.impl;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
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

import com.authlete.cose.*;
import io.mosip.cwtsign.constant.CWTConstant;
import io.mosip.cwtsign.dto.CWTSignRequestDto;
import io.mosip.cwtsign.dto.CWTSignResponseDto;
import io.mosip.cwtsign.dto.CWTVerifyRequestDto;
import io.mosip.cwtsign.dto.CWTVerifyResponseDto;
import io.mosip.cwtsign.logger.CWTSignLogger;
import io.mosip.cwtsign.service.CWTSignService;
import org.json.JSONObject;

import com.authlete.cbor.CBORByteArray;
import com.authlete.cbor.CBORDecoder;
import com.authlete.cbor.CBORItem;
import com.authlete.cbor.CBORPairList;
import com.authlete.cbor.CBORizer;
import com.authlete.cose.constants.COSEAlgorithms;
import com.authlete.cwt.CWT;
import com.authlete.cwt.CWTClaimsSet;
import com.authlete.cwt.CWTClaimsSetBuilder;
import org.springframework.stereotype.Service;

@Service
public class CWTSignServiceImpl implements CWTSignService{

    private static final int CLAIM_169 = 169;
    private static final String ISS = "www.mosip.io";

//    public static void main(String[] args) throws Exception {
//
//        if (args.length != 2) {
//            System.err.println("Please provide command line arguments.");
//            System.err.println("Argument 1 for operation. Eg: Sign or Verify");
//            System.err.println("Argument 2 for operation. Eg: File Path to read data");
//            System.exit(-1);
//        }
//
//        String ops = args[0];
//        String fileName = args[1];
//
//        if (!new File(fileName).exists()) {
//            System.err.println("File Not Found.");
//            System.exit(-2);
//        }
//
//        Path claim169FilePath = Path.of(fileName);
//        CWTSignServiceImpl signer = new CWTSignServiceImpl();
//
//        if (ops.equalsIgnoreCase("sign")) {
//            String claim169Data = Files.readString(claim169FilePath);
//            String cwtHexData = signer.cwtSign(claim169Data);
//            System.out.println("\n");
//            System.out.println(cwtHexData.toUpperCase());
//            System.out.println("\n");
//        } else if (ops.equalsIgnoreCase("verify")) {
//            String cwtData = Files.readString(claim169FilePath);
//            boolean valid = signer.cwtVerify(cwtData);
//            System.out.println("Signature is : " + (valid ? "Valid" : "Invalid"));
//        }
//    }

    @Override
    public CWTSignResponseDto cwtSign(CWTSignRequestDto requestDto) {

        String claim169 = requestDto.getClaim169Data();
        String claim169Data = "";
        int algorithm = COSEAlgorithms.EdDSA;

        Entry<String, EdECPrivateKey> edPrivKey = null;
        try {
            edPrivKey = getPrivateKey();
        } catch (Exception e) {
            throw new RuntimeException("Error while getting private key.", e);
        }

        // Protected header
        COSEProtectedHeader protectedHeader =
                new COSEProtectedHeaderBuilder().alg(algorithm).build();

        // Unprotected header
        COSEUnprotectedHeader unprotectedHeader =
                new COSEUnprotectedHeaderBuilder().kid(edPrivKey.getKey()).build();

        long currentTime = Instant.now().getEpochSecond();

        long expireTime = Instant.ofEpochSecond(currentTime)
                .plus(365, ChronoUnit.DAYS)
                .getEpochSecond();

        byte[] claim169Bytes = HexFormat.of().parseHex(claim169Data);

        CBORItem item = null;
        try {
            item = new CBORDecoder(claim169Bytes).next();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        CBORPairList pairList = (CBORPairList) item;

        Map<Object, Object> claim169Map = pairList.parse();

        for (Object key: claim169Map.keySet()){
            if (((Integer)key) == 62) {
                Map<Object, Object> photoDataMap = (Map) claim169Map.get(key);
                String photoData = (String) photoDataMap.get(Integer.valueOf(0));
                byte[] photoBytes = HexFormat.of().parseHex(photoData);
                photoDataMap.put(0, photoBytes);
                claim169Map.put(62, photoDataMap);
                break;
            }
        }

        CBORPairList updatedPairList = (CBORPairList)new CBORizer().cborizeMap(claim169Map);
        byte[] claim169Bts = updatedPairList.encode();

        // Payload
        CWTClaimsSet claimsSet = new CWTClaimsSetBuilder()
                .iss(ISS)
                .exp(expireTime)
                .nbf(currentTime)
                .iat(currentTime)
                .put(CLAIM_169, claim169Bts)
                .build();

        CBORByteArray claim169Payload = new CBORByteArray(claimsSet.encode());

        SigStructure sigStructure = new SigStructureBuilder().signature1()
                .bodyAttributes(protectedHeader)
                .payload(claim169Payload)
                .build();
        // Create a signer with the private key.
        COSESigner signer = new COSESigner(edPrivKey.getValue());

        // Sign the Sig_structure (= generate a signature).
        byte[] signature = null;
        try {
            signature = signer.sign(sigStructure, algorithm);
        } catch (COSEException e) {
            throw new RuntimeException(e);
        }

        COSESign1 sign1 = new COSESign1Builder()
                .protectedHeader(protectedHeader)
                .unprotectedHeader(unprotectedHeader)
                .payload(claim169Payload)
                .signature(signature)
                .build();
        CWT cwt = new CWT(sign1);

        CWTSignResponseDto responseDto = new CWTSignResponseDto();
        responseDto.setSuccess(true);
        responseDto.setMessage("CWT Signed Successfully");
        responseDto.setCwtHexData(cwt.encodeToHex());
        return responseDto;
    }

    private Entry<String, EdECPrivateKey> getPrivateKey() throws Exception {

        InputStream inputStream = CWTSignServiceImpl.class.getClassLoader().getResourceAsStream("key.jwk");

        String keyContent = "";
        if (Objects.nonNull(inputStream)) {
            keyContent = new String(inputStream.readAllBytes());
        } else {
            Path keyFilePath = Path.of("../resources/key.jwk");
            keyContent = Files.readString(keyFilePath);
        }
        if (keyContent.length() == 0) {
            throw new Exception("Key File not found.");
        }

        JSONObject jsonObject = new JSONObject(keyContent);
        String keyValueD = jsonObject.getString("d");
        String keyId = jsonObject.getString("kid");

        byte[] keyBytesD = Base64.getUrlDecoder().decode(keyValueD);

        KeyFactory keyFactory = KeyFactory.getInstance("Ed25519");
        EdECPrivateKeySpec privateSpec = new EdECPrivateKeySpec(NamedParameterSpec.ED25519, keyBytesD);
        EdECPrivateKey edPrivateKey = (EdECPrivateKey) keyFactory.generatePrivate(privateSpec);

        return new SimpleEntry<>(keyId, edPrivateKey);
    }

    @Override
    public CWTVerifyResponseDto cwtVerify(CWTVerifyRequestDto requestDto) throws Exception {

        String cwtSignedData = requestDto.getCwtSignedData();
        Entry<String, EdECPublicKey> edPublicKey = getPublicKey();

        COSEVerifier verifier = new COSEVerifier(edPublicKey.getValue());

        byte[] encodedCWT = HexFormat.of().parseHex(cwtSignedData);
        CWT cwt = (CWT)new CBORDecoder(encodedCWT).next();
        COSEMessage message = cwt.getMessage();

        COSESign1 sign1 = (COSESign1)message;
        boolean valid = verifier.verify(sign1);
        CWTClaimsSet claimsSet = CWTClaimsSet.build(sign1.getPayload());
        Date date = claimsSet.getExp();
        long exp = date.getTime()/1000;
        long currentTime = Instant.now().getEpochSecond();

        CWTVerifyResponseDto responseDto = new CWTVerifyResponseDto();
        responseDto.setSuccess(true);
        responseDto.setMessage("CWT Verified Successfully");
        responseDto.setValid(valid);
        responseDto.setStatus(valid ? "Valid" : "Invalid");
        return responseDto;
    }


    private Entry<String, EdECPublicKey> getPublicKey() throws Exception {

        InputStream inputStream = CWTSignServiceImpl.class.getClassLoader().getResourceAsStream("key.jwk");

        String keyContent = "";
        if (Objects.nonNull(inputStream)) {
            keyContent = new String(inputStream.readAllBytes());
        } else {
            Path keyFilePath = Path.of("../resources/key.jwk");
            keyContent = Files.readString(keyFilePath);
        }
        if (keyContent.length() == 0) {
            throw new Exception("Key File not found.");
        }

        JSONObject jsonObject = new JSONObject(keyContent);
        String keyValueX = jsonObject.getString("x");
        String keyId = jsonObject.getString("kid");

        byte[] keyBytesX = Base64.getUrlDecoder().decode(keyValueX);
        int keyLen = keyBytesX.length;
        boolean xBit = (keyBytesX[keyLen - 1] & 0x80) != 0;
        keyBytesX[keyLen - 1] = (byte)(keyBytesX[keyLen - 1] & 0x7f);

        byte[] publicKeyBytesBE = new byte[keyLen];
        for(int i = 0; i < keyLen; i++) {
            publicKeyBytesBE[i] = keyBytesX[keyLen - 1 - i];
        }

        BigInteger publicKeyY = new BigInteger(1, publicKeyBytesBE);

        KeyFactory keyFactory = KeyFactory.getInstance("Ed25519");
        EdECPublicKeySpec publicKeySpec = new EdECPublicKeySpec(NamedParameterSpec.ED25519,
                new EdECPoint(xBit, publicKeyY));

        EdECPublicKey edPublicKey = (EdECPublicKey) keyFactory.generatePublic(publicKeySpec);

        return new SimpleEntry<>(keyId, edPublicKey);
    }
}
