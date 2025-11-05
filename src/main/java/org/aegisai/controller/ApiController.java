package org.aegisai.controller;

import org.aegisai.dto.AnalysisDto;
import org.aegisai.dto.VulnerabilitiesDto;
import org.aegisai.service.ApiService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

import java.util.List;
import java.util.Map;

@RestController
public class ApiController {

    private final ApiService apiService;

    public ApiController(ApiService apiService) {
        this.apiService = apiService;
    }

    @PostMapping("/api/scan-vulnerability")
    public List<VulnerabilitiesDto> requestApi(@RequestBody AnalysisDto analysisDto) {
        return apiService.request(analysisDto);
    }

    @PostMapping("/api/token-count")
    public ResponseEntity<Map> countTokens(@RequestBody String code) {
        String url = "http://localhost:8000/token-count"; // Python 서버 주소

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.TEXT_PLAIN);
        HttpEntity<String> entity = new HttpEntity<>(code, headers);
        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<Map> resp = restTemplate.postForEntity(url, entity, Map.class);

        return ResponseEntity.ok(resp.getBody());
    }
}
