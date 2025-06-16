package io.mosip.cwtsign.controller;

import io.mosip.cwtsign.dto.CWTSignRequestDto;
import io.mosip.cwtsign.dto.CWTSignResponseDto;
import io.mosip.cwtsign.dto.CWTVerifyRequestDto;
import io.mosip.cwtsign.dto.CWTVerifyResponseDto;
import io.mosip.cwtsign.service.CWTSignService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import io.swagger.v3.oas.annotations.tags.Tag;


@CrossOrigin
@RestController
@RequestMapping("/api/v1/cwt")
@Tag(name = "CWT", description = "Controller for signing CWT (Compact Web Token) requests")
public class CWTSignController {

    @Autowired
    CWTSignService service;

    @PostMapping(value = "/sign")
    public CWTSignResponseDto signCWT(@RequestBody @Valid CWTSignRequestDto request) throws Exception {
        return service.cwtSign(request);
    }

    @PostMapping(value = "/verify")
    public CWTVerifyResponseDto verifyCWT(@RequestBody @Valid CWTVerifyRequestDto request) throws Exception {
        return service.cwtVerify(request);
    }
}
