package org.aegisai.service;


import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.cloud.vertexai.VertexAI;
import com.google.cloud.vertexai.api.GenerateContentResponse;
import com.google.cloud.vertexai.generativeai.GenerativeModel;
import com.google.cloud.vertexai.generativeai.ResponseHandler;

import org.aegisai.dto.VulnerabilitiesDto;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@Service
public class GeminiService {
    // input_test_api.py와 동일한 설정 값 사용
    private final String PROJECT_ID = "gen-lang-client-0539365210";
    private final String LOCATION = "us-central1";
    // Vertex AI에서 사용하는 Gemini 모델 엔드포인트 URL
    private final String MODEL_NAME = "gemini-2.0-flash-exp";
    private final GenerativeModel model;
    private final ObjectMapper objectMapper;
    private final String ENDPOINT = String.format("projects/%s/locations/%s/publishers/google/models/gemini-2.0-flash-exp", PROJECT_ID, LOCATION);

    public GeminiService(ObjectMapper objectMapper) throws IOException {
        this.objectMapper = objectMapper;
        // 1. VertexAI 클라이언트 초기화 (인증은 GOOGLE_APPLICATION_CREDENTIALS 자동 사용)
        VertexAI vertexAI = new VertexAI(PROJECT_ID, LOCATION);

        // 2. 사용할 GenerativeModel 초기화
        this.model = new GenerativeModel(MODEL_NAME, vertexAI);
    }

    /**
     * Gemini API를 호출하여 보안 취약점 분석 결과를 List<VulnerabilitiesDto> 형태로 반환합니다.
     */

    public String reasonCodebert(String vulnerableCode) {
        try {
            // 1. 프롬프트 생성 (buildPrompt 메서드는 삭제 가능)
            String prompt = String.format(
                    "당신은 Java 보안 분석 전문가입니다.\n\n" +
                            "# 분석 대상 코드:\n```java\n{SOURCE_CODE}\n```\n\n" + vulnerableCode,
                    "# AI 모델(CodeBERT) 분석 결과:\n- " +
                            "판단: {Label_1}\n- " +
                            "# 요청사항:\n위 코드가 '{PREDICTION}'로 분류된 기술적 근거를 설명해주세요.\n\n" +
                            "다음 JSON 형식으로 응답해주세요:\n{\n  \"reasoning\": \"" +
                            "CodeBERT가 이 코드를 {PREDICTION}로 판단한 주요 이유 (150자 이내)\",\n  \"" +
                            "keyIndicators\": [\n    \"판단의 근거가 된 핵심 코드 패턴 " +
                            "1\",\n    \"판단의 근거가 된 핵심 코드 패턴 " +
                            "2\",\n    \"판단의 근거가 된 핵심 코드 패턴 " +
                            "3\"\n  ],\n  \"riskFactors\": [\n    \"발견된 보안 위험 요소 " +
                            "1\",\n    \"발견된 보안 위험 요소 " +
                            "2\"\n  ],\n  \"confidence\": \"" +
                           // "신뢰도가 {CONFIDENCE}%인 이유에 대한 간단한 설명\"\n}\n\n" +
                            "주의사항:\n- JSON만 응답하고 다른 텍스트는 포함하지 마세요\n- " +
                            "마크다운 코드 블록(```)을 사용하지 마세요\n- 기술적이고 구체적으로 설명하세요",
                    vulnerableCode
            );

            // 2. API 호출
            GenerateContentResponse response = this.model.generateContent(prompt);

            // 3. 응답 텍스트 추출
            String jsonResponse = ResponseHandler.getText(response);

            // 4. JSON 정제 (마크다운 코드 블록 제거)
            jsonResponse = cleanJsonResponse(jsonResponse);

            return jsonResponse;

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public String reasonCodet5(String vulnerableCode, String fixedcode) {
        try {
            // 1. 프롬프트 생성 (buildPrompt 메서드는 삭제 가능)
            String prompt = "당신은 Java 보안 및 코드 리팩토링 전문가입니다.\n\n# 원본 코드 (취약점 존재):\n```java\n{ORIGINAL_CODE}\n```\n\n# AI 모델(CodeT5)이 수정한 코드:\n```java\n{FIXED_CODE}\n```\n\n# 취약점 유형: {VULNERABILITY_TYPE}\n\n# 요청사항:\nCodeT5가 위와 같이 코드를 수정한 기술적 근거와 보안 개선 사항을 설명해주세요.\n\n다음 JSON 형식으로 응답해주세요:\n{\n  \"fixReasoning\": \"CodeT5가 이렇게 수정한 주요 이유 (150자 이내)\",\n  \"changedPatterns\": [\n    {\n      \"before\": \"변경 전 코드 패턴\",\n      \"after\": \"변경 후 코드 패턴\",\n      \"reason\": \"이 변경이 필요한 이유\"\n    }\n  ],\n  \"securityImprovements\": [\n    \"개선된 보안 사항 1\",\n    \"개선된 보안 사항 2\"\n  ],\n  \"preventedAttacks\": [\n    \"이 수정으로 방지할 수 있는 공격 유형 1\",\n    \"이 수정으로 방지할 수 있는 공격 유형 2\"\n  ],\n  \"additionalRecommendations\": \"추가 보안 권장사항 (선택사항)\"\n}\n\n주의사항:\n- JSON만 응답하고 다른 텍스트는 포함하지 마세요\n- 마크다운 코드 블록(```)을 사용하지 마세요\n- 변경 사항을 구체적으로 비교 설명하세요";

            // 2. API 호출
            GenerateContentResponse response = this.model.generateContent(prompt);

            // 3. 응답 텍스트 추출
            String jsonResponse = ResponseHandler.getText(response);

            // 4. JSON 정제 (마크다운 코드 블록 제거)
            jsonResponse = cleanJsonResponse(jsonResponse);

            return jsonResponse;

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public List<VulnerabilitiesDto> analyzeVulnerabilities(String vulnerableCode, String fixedCode) {
        try {
            // 1. 프롬프트 생성 (buildPrompt 메서드는 삭제 가능)
            String prompt = String.format(
                    "당신은 Java 보안 전문가입니다.\n" +
                            "제공된 'Before' 코드의 모든 보안 취약점과 'After' 코드가 이 문제들을 어떻게 해결했는지 분석해주세요.\n\n" +
                            "## [Before] 취약한 코드:\n```java\n%s\n```\n\n" + vulnerableCode,
                    "## [After] 수정된 코드:\n```java\n%s\n```\n\n" + fixedCode,
                    "발견된 모든 취약점에 대해 다음 JSON 배열 형식으로 정확하게 응답해주세요:\n" +
                            "[\n" +
                            "  {\n" +
                            "    \"message\": \"보안 취약점과 해결 방법에 대한 명확하고 간결한 설명 (200자 이내)\",\n" +
                            "    \"lineNumber\": 문제가 발생한 라인 번호 (정수),\n" +
                            "    \"codeSnippet\": \"취약한 코드의 핵심 부분 (한 줄)\",\n" +
                            "    \"severity\": \"Critical\", \"High\", \"Medium\", \"Low\" 중 하나,\n" +
                            "    \"cweLink\": \"https://cwe.mitre.org/data/definitions/XXX.html\" 형식의 CWE 링크\n" +
                            "  }\n" +
                            "]\n\n" +
                            "주의사항:\n" +
                            "- 반드시 JSON 배열 형태로 응답하세요\n" +
                            "- 취약점이 여러 개라면 배열에 모두 포함하세요\n" +
                            "- 취약점이 하나만 있어도 배열 형태 [ {...} ]로 응답하세요\n" +
                            "- JSON만 응답하고 다른 텍스트는 포함하지 마세요\n" +
                            "- 마크다운 코드 블록(```)을 사용하지 마세요"
            );

            // 2. API 호출
            GenerateContentResponse response = this.model.generateContent(prompt);

            // 3. 응답 텍스트 추출
            String jsonResponse = ResponseHandler.getText(response);

            // 4. JSON 정제 (마크다운 코드 블록 제거)
            jsonResponse = cleanJsonResponse(jsonResponse);

            // 5. JSON을 List<VulnerabilitiesDto>로 파싱
            return objectMapper.readValue(
                    jsonResponse,
                    new TypeReference<List<VulnerabilitiesDto>>() {
                    }
            );

        } catch (Exception e) {
            e.printStackTrace();
            // 에러 발생 시 빈 리스트 반환
            return new ArrayList<>();
        }
    }

    private String cleanJsonResponse(String response) {
        // ```json ... ``` 형태 제거
        response = response.trim();
        if (response.startsWith("```json")) {
            response = response.substring(7);
        } else if (response.startsWith("```")) {
            response = response.substring(3);
        }
        if (response.endsWith("```")) {
            response = response.substring(0, response.length() - 3);
        }

        return response.trim();
    }

}