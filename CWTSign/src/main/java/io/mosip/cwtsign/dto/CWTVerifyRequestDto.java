package io.mosip.cwtsign.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CWTVerifyRequestDto {
    
    private String cwtSignedData;
}