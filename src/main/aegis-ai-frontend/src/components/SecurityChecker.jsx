import React, { useState, useEffect } from 'react';
import { Shield, AlertTriangle, CheckCircle, Code, Download, TrendingUp, Zap, ChevronDown, Info, X, Lightbulb } from 'lucide-react';
import { scanVulnerability, getTokenCount } from '../api/api';

export default function EnhancedSecurityChecker() {
  const [inputCode, setInputCode] = useState('');
  const language = 'Java'; // Java로 고정 
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [result, setResult] = useState(null);
  const [tokenCount, setTokenCount] = useState(0);
  const [characterCount, setCharacterCount] = useState(0);
  const [vulnerableLines, setVulnerableLines] = useState(new Set());
  const [safeLines, setSafeLines] = useState(new Set());
  const [showCopyNotification, setShowCopyNotification] = useState(false);
  const [notificationMessage, setNotificationMessage] = useState('');
  const lineNumbersRef = React.useRef(null);
  const textareaRef = React.useRef(null);
  
  // 🆕 XAI 팝업 상태
  const [xaiPopup, setXaiPopup] = useState({
    show: false,
    type: '', // 'detection' or 'fix'
    title: '',
    content: '',
    modelInfo: ''
  });

  // 실시간 토큰 및 문자 카운터
  useEffect(() => {
    const debounceMs = 300;
    let mounted = true;
    const timer = setTimeout(async () => {
      const charsLocal = inputCode.length;
      setCharacterCount(charsLocal);

      if (!inputCode || inputCode.trim().length === 0) {
        setTokenCount(0);
        detectVulnerableLinesRealtime();
        return;
      }

      try {
        const result = await getTokenCount(inputCode);
        
        if (!mounted) return;

        if (result.success && result.data) {
          setTokenCount(result.data.tokens);
          setCharacterCount(result.data.chars);
        } else {
          console.warn('토큰 카운트 API 실패, 폴백 사용:', result.error);
          setTokenCount(result.data.tokens);
          setCharacterCount(result.data.chars);
        }
      } catch (err) {
        console.error('토큰 카운트 예외:', err);
        const fallback = inputCode.split(/\s+/).filter(t => t.length > 0).length;
        if (mounted) {
          setTokenCount(fallback);
          setCharacterCount(inputCode.length);
        }
      }

      detectVulnerableLinesRealtime();
    }, debounceMs);

    return () => {
      mounted = false;
      clearTimeout(timer);
    };
  }, [inputCode, language]);

  // 실시간 취약 라인 감지 (Java 전용)
  const detectVulnerableLinesRealtime = () => {
    const lines = inputCode.split('\n');
    const vulnLines = new Set();
    const okLines = new Set();
    
    lines.forEach((line, idx) => {
      const lineNum = idx + 1;
      let isVulnerable = false;
      
      // Java 취약점 패턴 감지
      if ((line.includes('Statement') && line.includes('+')) || 
          line.includes('executeQuery') && inputCode.includes('+')) {
        isVulnerable = true;
      }
      if (line.includes('md5') || line.includes('MD5') || line.includes('SHA1')) {
        isVulnerable = true;
      }
      if (line.includes('printStackTrace')) {
        isVulnerable = true;
      }
      
      if (isVulnerable) {
        vulnLines.add(lineNum);
      } else if (line.trim().length > 0) {
        okLines.add(lineNum);
      }
    });
    
    setVulnerableLines(vulnLines);
    setSafeLines(okLines);
  };

  // 🆕 XAI 설명 생성 (임시 더미 데이터)
  const generateXAIExplanation = (vuln, type) => {
    if (type === 'detection') {
      return {
        modelInfo: '🤖 GraphCodeBERT + Gemini API',
        title: '왜 이 코드가 취약한가요?',
        content: `GraphCodeBERT 모델이 코드의 추상 구문 트리(AST)를 분석한 결과, 이 패턴은 ${vuln.type} 취약점의 전형적인 특징을 보입니다.\n\n` +
                 `🔍 탐지 근거:\n` +
                 `• 사용자 입력값이 검증 없이 직접 사용됨\n` +
                 `• 안전하지 않은 함수 호출 패턴 발견\n` +
                 `• 보안 가이드라인 위반 확인\n\n` +
                 `💡 Gemini 분석:\n"${vuln.description}"`
      };
    } else {
      return {
        modelInfo: '🛠️ CodeT5 + Gemini API',
        title: '어떻게 수정했나요?',
        content: `CodeT5 모델이 10만 개 이상의 보안 패치 사례를 학습하여 최적의 수정 방안을 생성했습니다.\n\n` +
                 `✅ 수정 전략:\n` +
                 `• ${vuln.recommendation}\n` +
                 `• 업계 표준 보안 패턴 적용\n` +
                 `• 성능 영향 최소화\n\n` +
                 `💡 Gemini 설명:\n"${vuln.impact} 이를 방지하기 위해 안전한 API를 사용하도록 코드를 재구성했습니다."`
      };
    }
  };

  // 🆕 XAI 팝업 표시 핸들러
  const showXAIExplanation = (vuln, type) => {
    const explanation = generateXAIExplanation(vuln, type);
    setXaiPopup({
      show: true,
      type: type,
      title: explanation.title,
      content: explanation.content,
      modelInfo: explanation.modelInfo
    });
    
    // 5초 후 자동 닫기
    setTimeout(() => {
      setXaiPopup(prev => ({ ...prev, show: false }));
    }, 8000);
  };

  // 🆕 XAI 팝업 닫기
  const closeXAIPopup = () => {
    setXaiPopup({ show: false, type: '', title: '', content: '', modelInfo: '' });
  };

  // 취약점 분석
  const analyzeCode = async () => {
    if (!inputCode.trim()) {
      alert('분석할 코드를 입력해주세요.');
      return;
    }

    setIsAnalyzing(true);
    
    try {
      const result = await scanVulnerability(inputCode, language);
      
      if (result.success && result.data) {
        setResult({
          isVulnerable: result.data.vulnerabilities && result.data.vulnerabilities.length > 0,
          vulnerabilities: result.data.vulnerabilities || [],
          fixedCode: result.data.fixed_code || inputCode,
          securityScore: result.data.security_score || 100,
          scanTime: result.data.scan_time || '0s',
          statistics: result.data.statistics || {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0
          }
        });
        
        setIsAnalyzing(false);
        return;
      } else {
        throw new Error(result.error || '알 수 없는 오류');
      }
    } catch (error) {
      console.error('백엔드 API 호출 실패:', error);
      alert(`백엔드 서버와 연결할 수 없습니다.\n오류: ${error.message || error}\n\n데모 모드로 실행합니다.`);
    }
    
    // 데모 모드 (기존 코드 유지)
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    const vulnerabilities = [];
    
    if (language === 'Java') {
      if (inputCode.includes('Statement') && inputCode.includes('+')) {
        const lineNum = inputCode.split('\n').findIndex(l => (l.includes('Statement') || l.includes('executeQuery')) && inputCode.includes('+')) + 1;
        const badCodeLine = inputCode.split('\n')[lineNum - 1];
        vulnerabilities.push({
          type: 'CWE-89',
          title: 'SQL Injection 취약점',
          severity: 'critical',
          line: lineNum,
          description: 'SQL 쿼리를 문자열 연결(+)로 생성하면 외부 입력값이 직접 쿼리에 삽입되어 공격자가 임의의 SQL 명령을 실행할 수 있습니다.',
          impact: '공격자가 인증 우회, 데이터 유출, 데이터 변조, 시스템 손상을 일으킬 수 있습니다.',
          recommendation: 'PreparedStatement를 사용하여 파라미터화된 쿼리를 작성하세요.',
          originalCode: badCodeLine.trim(),
          fixedCode: 'PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");\npstmt.setString(1, userId);',
          reference: 'OWASP Top 10 - A03:2021 Injection'
        });
      }
      
      if (inputCode.includes('md5') || inputCode.includes('MD5')) {
        const lineNum = inputCode.split('\n').findIndex(l => l.includes('md5') || l.includes('MD5')) + 1;
        const badCodeLine = inputCode.split('\n')[lineNum - 1];
        vulnerabilities.push({
          type: 'CWE-327',
          title: '약한 암호화 알고리즘 사용',
          severity: 'high',
          line: lineNum,
          description: 'MD5는 충돌 공격에 취약한 해시 알고리즘입니다. 비밀번호 저장용으로 사용해서는 안 됩니다.',
          impact: '공격자가 레인보우 테이블이나 GPU 기반 크래킹을 통해 해시를 역산할 수 있습니다.',
          recommendation: '비밀번호 저장에는 bcrypt, Argon2를 사용하세요. 일반 해시는 SHA-256 이상을 사용하세요.',
          originalCode: badCodeLine.trim(),
          fixedCode: 'MessageDigest md = MessageDigest.getInstance("SHA-256");',
          reference: 'NIST - Deprecated Hash Algorithms'
        });
      }
      
      if (inputCode.includes('printStackTrace')) {
        const lineNum = inputCode.split('\n').findIndex(l => l.includes('printStackTrace')) + 1;
        const badCodeLine = inputCode.split('\n')[lineNum - 1];
        vulnerabilities.push({
          type: 'CWE-209',
          title: '민감한 정보 노출',
          severity: 'medium',
          line: lineNum,
          description: 'printStackTrace()는 시스템 경로, 버전 정보 등 민감한 정보를 노출시킵니다.',
          impact: '공격자가 시스템 구조를 파악하여 표적 공격을 수행할 수 있습니다.',
          recommendation: '로깅 프레임워크(Log4j, SLF4J)를 사용하고, 프로덕션 환경에서는 상세 에러를 숨기세요.',
          originalCode: badCodeLine.trim(),
          fixedCode: 'logger.error("An error occurred", e); // 로그에만 기록',
          reference: 'OWASP - Improper Error Handling'
        });
      }
    }
    
    const score = Math.max(0, 100 - (vulnerabilities.length * 20));
    const stats = {
      critical: vulnerabilities.filter(v => v.severity === 'critical').length,
      high: vulnerabilities.filter(v => v.severity === 'high').length,
      medium: vulnerabilities.filter(v => v.severity === 'medium').length,
      low: vulnerabilities.filter(v => v.severity === 'low').length
    };
    
    let fixedCode = inputCode;
    vulnerabilities.forEach(vuln => {
      if (vuln.originalCode) {
        fixedCode = fixedCode.replace(vuln.originalCode, vuln.fixedCode);
      }
    });
    
    setResult({
      isVulnerable: vulnerabilities.length > 0,
      vulnerabilities,
      fixedCode,
      securityScore: score,
      scanTime: '2.3s',
      statistics: stats
    });
    
    setIsAnalyzing(false);
  };

  // 스크롤 동기화
  const handleScroll = (e) => {
    if (lineNumbersRef.current) {
      lineNumbersRef.current.scrollTop = e.target.scrollTop;
    }
  };

  // 라인 넘버 생성
  const renderLineNumbers = () => {
    const lines = inputCode.split('\n');
    return lines.map((_, idx) => {
      const lineNum = idx + 1;
      const isVuln = vulnerableLines.has(lineNum);
      const isSafe = safeLines.has(lineNum);
      
      return (
        <div
          key={lineNum}
          className={`px-2 text-right select-none leading-6 ${
            isVuln ? 'bg-red-500/10 text-red-400 font-bold' :
            isSafe ? 'text-slate-600' :
            'text-slate-700'
          }`}
        >
          {lineNum}
        </div>
      );
    });
  };

  // Severity 색상
  const getSeverityBadgeColor = (severity) => {
    switch(severity) {
      case 'critical': return 'border-red-500 bg-red-500/10 text-red-400';
      case 'high': return 'border-orange-500 bg-orange-500/10 text-orange-400';
      case 'medium': return 'border-yellow-500 bg-yellow-500/10 text-yellow-400';
      case 'low': return 'border-blue-500 bg-blue-500/10 text-blue-400';
      default: return 'border-slate-500 bg-slate-500/10 text-slate-400';
    }
  };

  // Score 색상
  const getScoreColor = (score) => {
    if (score >= 80) return 'text-green-400';
    if (score >= 60) return 'text-yellow-400';
    if (score >= 40) return 'text-orange-400';
    return 'text-red-400';
  };

  // 코드 복사
  const handleCopyCode = () => {
    navigator.clipboard.writeText(result.fixedCode);
    setNotificationMessage('수정된 코드가 복사되었습니다! ✨');
    setShowCopyNotification(true);
    setTimeout(() => setShowCopyNotification(false), 2000);
  };

  // 리포트 다운로드
  const downloadReport = () => {
    const report = `=== AegisAI 보안 분석 리포트 ===\n\n` +
      `분석 언어: ${language}\n` +
      `보안 점수: ${result.securityScore}/100\n` +
      `스캔 시간: ${result.scanTime}\n\n` +
      `=== 발견된 취약점 (${result.vulnerabilities.length}개) ===\n\n` +
      result.vulnerabilities.map((v, i) => 
        `${i+1}. ${v.title} (${v.type})\n` +
        `   심각도: ${v.severity}\n` +
        `   라인: ${v.line}\n` +
        `   설명: ${v.description}\n` +
        `   수정방법: ${v.recommendation}\n\n`
      ).join('') +
      `=== 수정된 코드 ===\n\n${result.fixedCode}`;
    
    const blob = new Blob([report], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `aegis-report-${Date.now()}.txt`;
    a.click();
    
    setNotificationMessage('리포트 다운로드 완료! 📥');
    setShowCopyNotification(true);
    setTimeout(() => setShowCopyNotification(false), 2000);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 text-slate-100">
      {/* Header */}
      <header className="bg-slate-900/80 backdrop-blur-sm border-b border-slate-800 sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="bg-gradient-to-br from-blue-500 to-purple-600 p-2 rounded-lg">
              <Shield className="w-6 h-6 text-white" />
            </div>
            <div>
              <h1 className="text-xl font-bold bg-gradient-to-r from-blue-400 to-purple-400 bg-clip-text text-transparent">
                AegisAI
              </h1>
              <p className="text-xs text-slate-500">AI 기반 보안 취약점 분석</p>
            </div>
          </div>
          
          <div className="flex items-center gap-4 text-sm">
            <div className="flex items-center gap-2 bg-slate-800/50 px-3 py-1.5 rounded-lg">
              <Zap className="w-4 h-4 text-yellow-400" />
              <span className="text-slate-400">토큰:</span>
              <span className="font-mono font-bold text-yellow-400">{tokenCount}</span>
            </div>
            <div className="flex items-center gap-2 bg-slate-800/50 px-3 py-1.5 rounded-lg">
              <Code className="w-4 h-4 text-blue-400" />
              <span className="text-slate-400">문자:</span>
              <span className="font-mono font-bold text-blue-400">{characterCount}</span>
            </div>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-6 py-6 grid grid-cols-2 gap-6 h-[calc(100vh-88px)]">
        {/* Left Panel */}
        <div className="flex flex-col gap-4 overflow-hidden">
          {/* Analyze Button */}
          <div className="flex gap-3 flex-shrink-0">
            {/* Java 고정 표시 */}
            <div className="flex-1 bg-slate-900 border border-slate-800 rounded-lg px-4 py-2 text-white flex items-center gap-2">
              <Code className="w-4 h-4 text-blue-400" />
              <span className="font-semibold">Java</span>
              <span className="text-xs text-slate-500 ml-auto">언어 고정</span>
            </div>
            
            <button
              onClick={analyzeCode}
              disabled={isAnalyzing || !inputCode.trim()}
              className="flex-1 bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-500 hover:to-purple-500 disabled:from-slate-700 disabled:to-slate-700 text-white font-semibold py-2 px-6 rounded-lg transition-all flex items-center justify-center gap-2 disabled:cursor-not-allowed"
            >
              {isAnalyzing ? (
                <>
                  <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  분석 중...
                </>
              ) : (
                <>
                  <Shield className="w-4 h-4" />
                  취약점 분석
                </>
              )}
            </button>
          </div>

          {/* Code Input */}
          <div className="flex-1 bg-slate-900 rounded-xl border border-slate-800 overflow-hidden flex flex-col">
            <div className="bg-slate-800/50 px-4 py-2 border-b border-slate-700 flex items-center justify-between flex-shrink-0">
              <h3 className="font-semibold text-white text-sm">코드 입력</h3>
              <span className="text-xs text-slate-500">
                {vulnerableLines.size > 0 && (
                  <span className="text-red-400 font-semibold">
                    {vulnerableLines.size}개 취약 라인 감지
                  </span>
                )}
              </span>
            </div>
            <div className="flex-1 flex overflow-hidden">
              <div
                ref={lineNumbersRef}
                className="bg-slate-800/30 overflow-hidden flex-shrink-0 w-12 text-xs"
              >
                {renderLineNumbers()}
              </div>
              <textarea
                ref={textareaRef}
                value={inputCode}
                onChange={(e) => setInputCode(e.target.value)}
                onScroll={handleScroll}
                placeholder="분석할 코드를 입력하세요..."
                className="flex-1 bg-transparent text-white font-mono text-sm p-3 focus:outline-none resize-none leading-6"
                spellCheck={false}
              />
            </div>
          </div>
        </div>

        {/* Right Panel */}
        <div className="flex flex-col gap-4 overflow-hidden">
          {/* Security Score Card */}
          {result && (
            <div className="bg-slate-900 rounded-xl border border-slate-800 p-4 flex-shrink-0">
              <div className="flex items-center gap-4">
                {/* Score Circle */}
                <div className="relative w-24 h-24 flex-shrink-0">
                  <svg className="w-full h-full transform -rotate-90">
                    <circle cx="48" cy="48" r="42" stroke="currentColor" strokeWidth="8" fill="none" className="text-slate-800" />
                    <circle 
                      cx="48" cy="48" r="42" 
                      stroke="currentColor" 
                      strokeWidth="8" 
                      fill="none" 
                      strokeDasharray={`${result.securityScore * 2.64} 999`}
                      className={getScoreColor(result.securityScore)}
                      strokeLinecap="round"
                    />
                  </svg>
                  <div className="absolute inset-0 flex flex-col items-center justify-center">
                    <span className={`text-2xl font-bold ${getScoreColor(result.securityScore)}`}>
                      {result.securityScore}
                    </span>
                  </div>
                </div>
                
                {/* Stats */}
                <div className="flex-1 grid grid-cols-4 gap-2">
                  <div className="text-center">
                    <div className={`text-2xl font-bold text-red-400`}>{result.statistics.critical}</div>
                    <div className="text-xs text-slate-500">Critical</div>
                  </div>
                  <div className="text-center">
                    <div className={`text-2xl font-bold text-orange-400`}>{result.statistics.high}</div>
                    <div className="text-xs text-slate-500">High</div>
                  </div>
                  <div className="text-center">
                    <div className={`text-2xl font-bold text-yellow-400`}>{result.statistics.medium}</div>
                    <div className="text-xs text-slate-500">Medium</div>
                  </div>
                  <div className="text-center">
                    <div className={`text-2xl font-bold text-blue-400`}>{result.statistics.low}</div>
                    <div className="text-xs text-slate-500">Low</div>
                  </div>
                </div>
                
                {/* Download Button */}
                <button
                  onClick={downloadReport}
                  className="flex-shrink-0 bg-slate-800 hover:bg-slate-700 text-white px-4 py-2 rounded-lg flex items-center gap-2 transition-colors"
                >
                  <Download className="w-4 h-4" />
                  <span className="text-sm">리포트</span>
                </button>
              </div>
            </div>
          )}

          {/* Fixed Code Section */}
          {result && result.vulnerabilities.length > 0 && (
            <div className="bg-slate-900 rounded-xl border border-slate-800 flex flex-col h-56 flex-shrink-0">
              <div className="bg-slate-800/50 px-4 py-2 border-b border-slate-700 flex-shrink-0 flex items-center justify-between">
                <h3 className="font-semibold text-white text-sm flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-green-400" />
                  전체 수정된 코드
                </h3>
                <button
                  onClick={handleCopyCode}
                  className="text-xs bg-slate-700 hover:bg-slate-600 text-slate-200 px-3 py-1 rounded flex items-center gap-1 transition-colors"
                >
                  <Code className="w-3 h-3" />
                  복사
                </button>
              </div>
              <div className="flex-1 overflow-auto p-3">
                <pre className="font-mono text-xs text-green-300 whitespace-pre-wrap break-words">
                  {result.fixedCode}
                </pre>
              </div>
            </div>
          )}

          {/* Vulnerabilities List - Scrollable */}
          <div className="flex-1 bg-slate-900 rounded-xl border border-slate-800 overflow-hidden flex flex-col">
            <div className="bg-slate-800/50 px-4 py-3 border-b border-slate-700 flex items-center justify-between flex-shrink-0">
              <h3 className="font-semibold text-white text-sm flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-orange-400" />
                발견된 취약점
                {result && <span className="text-slate-500">({result.vulnerabilities.length})</span>}
              </h3>
            </div>
            
            <div className="flex-1 overflow-y-auto p-4">
              {!result ? (
                <div className="h-full flex flex-col items-center justify-center text-slate-500">
                  <Shield className="w-12 h-12 mb-3 opacity-20" />
                  <p className="text-sm text-center">코드를 분석하면<br/>취약점 정보가 표시됩니다</p>
                </div>
              ) : result.vulnerabilities.length === 0 ? (
                <div className="h-full flex flex-col items-center justify-center text-green-400">
                  <CheckCircle className="w-12 h-12 mb-3" />
                  <p className="font-semibold">취약점 없음</p>
                  <p className="text-xs text-slate-500 mt-1">안전한 코드입니다 ✨</p>
                </div>
              ) : (
                <div className="space-y-3">
                  {result.vulnerabilities.map((vuln, idx) => (
                    <details key={idx} className="bg-slate-800/50 rounded-lg border border-slate-700 overflow-hidden group">
                      <summary className="p-3 cursor-pointer hover:bg-slate-800 transition-colors flex items-start justify-between">
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-1">
                            <span className="font-mono text-xs text-blue-400">{vuln.type}</span>
                            <span className={`px-2 py-0.5 rounded text-xs font-semibold border ${getSeverityBadgeColor(vuln.severity)}`}>
                              {vuln.severity.toUpperCase()}
                            </span>
                            <span className="text-xs text-slate-500">Line {vuln.line}</span>
                          </div>
                          <h4 className="font-semibold text-white text-sm">{vuln.title}</h4>
                        </div>
                        <ChevronDown className="w-4 h-4 text-slate-400 group-open:rotate-180 transition-transform flex-shrink-0 mt-1" />
                      </summary>
                      
                      <div className="p-4 pt-0 space-y-3 text-sm border-t border-slate-700">
                        {/* Description */}
                        <div>
                          <h5 className="text-xs font-semibold text-slate-400 mb-1 flex items-center gap-1">
                            <Info className="w-3 h-3" />
                            설명
                          </h5>
                          <p className="text-slate-300 leading-relaxed">{vuln.description}</p>
                        </div>
                        
                        {/* Impact */}
                        <div>
                          <h5 className="text-xs font-semibold text-red-400 mb-1">💥 보안 영향</h5>
                          <p className="text-slate-300 leading-relaxed">{vuln.impact}</p>
                        </div>
                        
                        {/* Recommendation */}
                        <div>
                          <h5 className="text-xs font-semibold text-green-400 mb-1">✅ 수정 방법</h5>
                          <p className="text-slate-300 leading-relaxed">{vuln.recommendation}</p>
                        </div>
                        
                        {/* 🆕 Code Comparison with XAI */}
                        <div className="grid grid-cols-2 gap-2">
                          {/* 취약한 코드 - 클릭 가능 */}
                          <div>
                            <h5 className="text-xs font-semibold text-red-400 mb-2 flex items-center gap-1">
                              ❌ 취약한 코드
                              <Lightbulb className="w-3 h-3 text-yellow-400" />
                            </h5>
                            <div 
                              className="bg-red-500/10 border border-red-500/30 rounded p-2 overflow-x-auto cursor-pointer hover:bg-red-500/20 hover:border-red-500/50 transition-all group/vuln"
                              onClick={() => showXAIExplanation(vuln, 'detection')}
                              title="클릭하여 AI 설명 보기"
                            >
                              <pre className="text-xs text-red-200 font-mono whitespace-pre-wrap break-all group-hover/vuln:text-red-100">{vuln.originalCode}</pre>
                              <div className="text-xs text-red-400 mt-1 opacity-0 group-hover/vuln:opacity-100 transition-opacity flex items-center gap-1">
                                <Lightbulb className="w-3 h-3" />
                                왜 취약한가요?
                              </div>
                            </div>
                          </div>
                          
                          {/* 수정된 코드 - 클릭 가능 */}
                          <div>
                            <h5 className="text-xs font-semibold text-green-400 mb-2 flex items-center gap-1">
                              ✓ 수정된 코드
                              <Lightbulb className="w-3 h-3 text-yellow-400" />
                            </h5>
                            <div 
                              className="bg-green-500/10 border border-green-500/30 rounded p-2 overflow-x-auto cursor-pointer hover:bg-green-500/20 hover:border-green-500/50 transition-all group/fix"
                              onClick={() => showXAIExplanation(vuln, 'fix')}
                              title="클릭하여 AI 설명 보기"
                            >
                              <pre className="text-xs text-green-200 font-mono whitespace-pre-wrap break-all group-hover/fix:text-green-100">{vuln.fixedCode}</pre>
                              <div className="text-xs text-green-400 mt-1 opacity-0 group-hover/fix:opacity-100 transition-opacity flex items-center gap-1">
                                <Lightbulb className="w-3 h-3" />
                                어떻게 수정했나요?
                              </div>
                            </div>
                          </div>
                        </div>
                        
                        {/* Reference */}
                        <div className="text-xs text-slate-500 italic">
                          📚 참고: {vuln.reference}
                        </div>
                      </div>
                    </details>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      </main>

      {/* Copy/Download Notification Toast */}
      {showCopyNotification && (
        <div className="fixed top-20 right-6 bg-green-600 text-white px-6 py-3 rounded-lg shadow-2xl flex items-center gap-3 animate-fade-in z-50 border border-green-500">
          <CheckCircle className="w-5 h-5" />
          <span className="font-semibold">{notificationMessage}</span>
        </div>
      )}

      {/* 🆕 XAI Explanation Popup Toast */}
      {xaiPopup.show && (
        <div className="fixed top-24 left-1/2 -translate-x-1/2 w-full max-w-2xl bg-gradient-to-br from-slate-800 to-slate-900 text-white p-6 rounded-2xl shadow-2xl border-2 border-blue-500/50 animate-slide-down z-50">
          {/* Header */}
          <div className="flex items-start justify-between mb-4">
            <div className="flex items-center gap-3">
              <div className="bg-gradient-to-br from-blue-500 to-purple-600 p-2 rounded-lg">
                <Lightbulb className="w-6 h-6 text-white" />
              </div>
              <div>
                <h3 className="text-lg font-bold">{xaiPopup.title}</h3>
                <p className="text-xs text-slate-400">{xaiPopup.modelInfo}</p>
              </div>
            </div>
            <button
              onClick={closeXAIPopup}
              className="text-slate-400 hover:text-white transition-colors p-1 hover:bg-slate-700 rounded"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
          
          {/* Content */}
          <div className="bg-slate-900/50 rounded-lg p-4 border border-slate-700">
            <pre className="text-sm text-slate-200 whitespace-pre-wrap leading-relaxed">
              {xaiPopup.content}
            </pre>
          </div>
          
          {/* Footer */}
          <div className="mt-4 flex items-center justify-between text-xs text-slate-500">
            <span>💡 설명 가능한 AI</span>
            <span>8초 후 자동으로 닫힙니다</span>
          </div>
        </div>
      )}

      <style jsx>{`
        @keyframes fade-in {
          from { opacity: 0; transform: translateY(-10px); }
          to { opacity: 1; transform: translateY(0); }
        }
        @keyframes slide-down {
          from { opacity: 0; transform: translate(-50%, -20px); }
          to { opacity: 1; transform: translate(-50%, 0); }
        }
        .animate-fade-in {
          animation: fade-in 0.3s ease-out;
        }
        .animate-slide-down {
          animation: slide-down 0.4s ease-out;
        }
      `}</style>
    </div>
  );
}