import torch
from transformers import (
    pipeline,
    AutoTokenizer,
    AutoModelForSeq2SeqLM
)
from peft import PeftModel
import time
import os

# ⭐️ Vertex AI 라이브러리 임포트
import vertexai
from vertexai.generative_models import GenerativeModel

# --- 1. 모델 및 토크나이저 경로 설정 ---
CLASSIFIER_MODEL = "mangsense/codebert_java"
FIXER_BASE_MODEL = "Salesforce/codet5-base"
FIXER_LORA_ADAPTER = "mangsense/codet5-base-clean-LoRA"
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"

# --- 2. ⭐️ Vertex AI 설정 ---
PROJECT_ID = "gen-lang-client-0539365210"
LOCATION = "us-central1"
GEMINI_MODEL_NAME = "gemini-2.0-flash-exp"

print(f"--- 🚀 파이프라인 초기화 시작 (Using: {DEVICE}) ---")

# --- 3. [0/3] 💬 설명기(Vertex AI Gemini) 로드 ---
gemini_model = None

# 시도할 모델 목록
MODEL_CANDIDATES = [
    "gemini-2.0-flash-exp",
    "gemini-1.5-flash",
    "gemini-1.5-pro",
]

try:
    print(f"\n[0/3] 💬 Vertex AI 인증 및 모델 로드 중...")
    
    # Vertex AI 초기화
    vertexai.init(project=PROJECT_ID, location=LOCATION)
    
    # 여러 모델 시도
    for model_name in MODEL_CANDIDATES:
        try:
            print(f"   🔄 시도: {model_name}...", end=" ")
            test_model = GenerativeModel(model_name)
            
            # 간단한 테스트
            response = test_model.generate_content("Hi")
            
            # 성공하면 저장
            gemini_model = test_model
            GEMINI_MODEL_NAME = model_name
            print(f"✅ 성공!")
            break
            
        except Exception as e:
            print(f"❌ 실패")
            continue
    
    if gemini_model:
        print(f"✅ 설명기(Gemini) 로드 완료! (Model: {GEMINI_MODEL_NAME}, Project: {PROJECT_ID})")
    else:
        print("❌ 사용 가능한 Gemini 모델을 찾을 수 없습니다.")
        print("   [해결책] 1. gcloud auth application-default login 실행")
        print(f"   [해결책] 2. {PROJECT_ID} 프로젝트의 'Vertex AI API' 활성화 확인")
    
except Exception as e:
    print(f"❌ Vertex AI (Gemini) 초기화 실패: {e}")
    print("   [해결책] 1. gcloud auth application-default login 실행")
    print(f"   [해결책] 2. gcloud services enable aiplatform.googleapis.com --project={PROJECT_ID}")
    gemini_model = None

# --- 4. [1/3] 🕵️ 분류기 (CodeBERT) 로드 ---
print(f"\n[1/3] 🕵️ 분류기 로드 중: {CLASSIFIER_MODEL}")
try:
    classifier = pipeline(
        "text-classification",
        model=CLASSIFIER_MODEL,
        device=0 if DEVICE == "cuda" else -1
    )
    print(f"분류기 레이블 맵: {classifier.model.config.id2label}")
    print(f"✅ 분류기 로드 완료")
except Exception as e:
    print(f"❌ 분류기 로드 실패: {e}")
    exit()

# --- 5. [2/3] 🛠️ 수정기 (CodeT5 + LoRA) 로드 ---
print(f"\n[2/3] 🛠️ 수정기 로드 중: {FIXER_BASE_MODEL} + {FIXER_LORA_ADAPTER}")
print(f"   📦 허깅페이스에서 LoRA 어댑터 다운로드 중...")
try:
    base_model = AutoModelForSeq2SeqLM.from_pretrained(
        FIXER_BASE_MODEL,
        load_in_8bit=True,
        device_map="auto"
    )
    fixer_tokenizer = AutoTokenizer.from_pretrained(FIXER_BASE_MODEL)
    
    fixer_model = PeftModel.from_pretrained(
        base_model, 
        FIXER_LORA_ADAPTER,
    )
    fixer_model.eval()
    
    print(f"✅ 수정기 로드 완료 (HuggingFace: {FIXER_LORA_ADAPTER})\n")
except Exception as e:
    print(f"❌ 수정기 로드 실패: {e}")
    print(f"   [해결책] 1. 모델이 public인지 확인: {FIXER_LORA_ADAPTER}")
    print(f"   [해결책] 2. 필요시 HuggingFace 토큰 설정: huggingface-cli login")
    exit()

# --- 6. ⭐️ Gemini 설명 함수 정의 ---
def explain_fix_with_gemini(vulnerable_code, fixed_code, max_retries=3):
    """
    Gemini API를 호출하여 코드 수정 사항을 자연어로 설명합니다.
    """
    if not gemini_model:
        return "⚠️ Gemini 모델이 로드되지 않아 설명을 생성할 수 없습니다."

    prompt = f"""
당신은 Java 보안 전문가입니다.
제공된 'Before' 코드의 보안 취약점과 'After' 코드가 이 문제를 어떻게 해결했는지 설명해주세요.
설명은 한국어로, 명확하고 간결하게 작성해주세요 (200자 이내).

## [Before] 취약한 코드:
```java
{vulnerable_code.strip()}
```

## [After] 수정된 코드:
```java
{fixed_code.strip()}
```

## [설명]:
"""
    
    print(f"--- 3. 💬 Gemini API 호출 (모델: {GEMINI_MODEL_NAME}) ---")
    
    for attempt in range(max_retries):
        try:
            response = gemini_model.generate_content(
                prompt,
                generation_config={
                    "temperature": 0.3,
                    "top_p": 0.8,
                    "top_k": 40,
                    "max_output_tokens": 512,
                }
            )
            
            print(f"✅ Gemini API 호출 성공!")
            return response.text
            
        except Exception as e:
            error_msg = str(e)
            print(f"⚠️ 시도 {attempt + 1}/{max_retries} 실패: {error_msg[:100]}...")
            
            if "quota" in error_msg.lower() or "429" in error_msg:
                print("   💡 API 할당량 초과. 잠시 후 재시도...")
                time.sleep(5)
            elif attempt < max_retries - 1:
                time.sleep(2)
            else:
                return f"❌ Gemini API 호출 최종 실패: {error_msg}"

# --- 7. 전체 파이프라인 함수 ---
def vulnerability_fix_pipeline(code_snippet):
    print("\n" + "="*50)
    print("--- 1. 🕵️ 취약점 분류 시작 ---")
    
    classification_result = classifier(code_snippet)[0]
    label = classification_result['label']
    score = classification_result['score']
    
    print(f"▶️  분류 결과: {label} (신뢰도: {score:.2%})")
    
    if label == 'LABEL_0':
        print("--- ✅ 코드가 안전합니다. 수정이 필요 없습니다. ---")
        print("="*50 + "\n")
        return code_snippet, "수정이 필요 없는 안전한 코드입니다."
    
    else:
        print("--- 2. 🛠️ 코드 수정 시작 (CodeT5 + LoRA) ---")
        
        task_prefix = "fix this vulnerable C/C++ function: "
        
        input_ids = fixer_tokenizer(
            task_prefix + code_snippet,
            return_tensors="pt",
            max_length=512,
            truncation=True
        ).input_ids.to(DEVICE)

        try:
            generated_ids = fixer_model.generate(
                input_ids=input_ids,
                max_length=512,
                num_beams=5,
                early_stopping=True
            )
            
            fixed_code = fixer_tokenizer.decode(
                generated_ids[0], 
                skip_special_tokens=True
            )
            
            print("--- ✅ 코드 수정이 완료되었습니다. ---")
            
            # Gemini 설명 호출
            explanation = explain_fix_with_gemini(code_snippet, fixed_code)
            
            print("="*50 + "\n")
            return fixed_code, explanation
        
        except Exception as e:
            print(f"❌ 코드 수정 중 오류 발생: {e}")
            return None, f"코드 수정 중 오류 발생: {e}"

# --- 8. 예제 2번: Command Injection ---
command_injection_example = """
import java.io.*;

public class CommandInjectionVulnerable {
    public void pingHost(String userInput) {
        try {
            String command = "ping -c 4 " + userInput;
            Runtime.getRuntime().exec(command);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
"""

print("\n\n" + "="*70)
print("🔍 예제 2번: Command Injection 취약점 테스트")
print("="*70)
print("\n--- 📄 원본 취약한 코드 ---")
print(command_injection_example)
print("----------------------------\n")

# 파이프라인 실행
fixed_code, explanation = vulnerability_fix_pipeline(command_injection_example)

if fixed_code:
    print("\n" + "="*70)
    print("--- 🛡️ 수정된 코드 ---")
    print("="*70)
    print(fixed_code)
    print("="*70)

if explanation:
    print("\n--- 💡 Gemini의 취약점 설명 ---")
    print(explanation)
    print("-"*70 + "\n")
