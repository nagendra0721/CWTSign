package io.mosip.cwtsign.service;

import io.mosip.cwtsign.dto.CWTSignRequestDto;
import io.mosip.cwtsign.dto.CWTSignResponseDto;
import io.mosip.cwtsign.dto.CWTVerifyRequestDto;
import io.mosip.cwtsign.dto.CWTVerifyResponseDto;

public interface CWTSignService {

    /**
     * Signs the given claim data and returns CWT hex string
     *
     * @param claim169Data the claim data to sign
     * @return CWT hex string
     * @throws Exception if signing fails
     */
    public CWTSignResponseDto cwtSign(CWTSignRequestDto requestDto) throws Exception;

    /**
     * Verifies the CWT signed data
     *
     * @param cwtSignedData the CWT signed data to verify
     * @return true if signature is valid and not expired, false otherwise
     * @throws Exception if verification fails
     */
    public CWTVerifyResponseDto cwtVerify(CWTVerifyRequestDto requestDto) throws Exception;
}
