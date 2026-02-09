#!/usr/bin/env python3
"""
================================================================================
ANÁLISE COMPLETA DOS RELATÓRIOS DE SEGURANÇA - PIPELINE DEVSECOPS
================================================================================
Pesquisa: Integração de Testes de Segurança Contínuos em Pipelines CI/CD
Aplicação alvo: DVWA (Damn Vulnerable Web Application)
Data de execução: Fevereiro 2026
================================================================================
"""
import json
import os
from collections import defaultdict
from datetime import datetime
from pathlib import Path

# ============================================================================
# VULNERABILIDADES CONHECIDAS DO DVWA
# Referência: https://github.com/digininja/DVWA
# ============================================================================
DVWA_KNOWN_VULNERABILITIES = {
    "web_application": {
        "SQL Injection": {
            "cwe": "CWE-89",
            "owasp": "A03:2021 - Injection",
            "description": "Permite injeção de comandos SQL em campos de entrada",
            "locations": ["vulnerabilities/sqli/", "vulnerabilities/sqli_blind/"]
        },
        "Cross-Site Scripting (XSS)": {
            "cwe": "CWE-79",
            "owasp": "A03:2021 - Injection",
            "description": "Permite execução de scripts maliciosos no navegador",
            "locations": ["vulnerabilities/xss_r/", "vulnerabilities/xss_s/", "vulnerabilities/xss_d/"]
        },
        "Command Injection": {
            "cwe": "CWE-78",
            "owasp": "A03:2021 - Injection",
            "description": "Permite execução de comandos do sistema operacional",
            "locations": ["vulnerabilities/exec/"]
        },
        "File Inclusion (LFI/RFI)": {
            "cwe": "CWE-98",
            "owasp": "A03:2021 - Injection",
            "description": "Permite inclusão de arquivos locais ou remotos",
            "locations": ["vulnerabilities/fi/"]
        },
        "File Upload": {
            "cwe": "CWE-434",
            "owasp": "A04:2021 - Insecure Design",
            "description": "Permite upload de arquivos maliciosos",
            "locations": ["vulnerabilities/upload/"]
        },
        "CSRF": {
            "cwe": "CWE-352",
            "owasp": "A01:2021 - Broken Access Control",
            "description": "Cross-Site Request Forgery",
            "locations": ["vulnerabilities/csrf/"]
        },
        "Weak Session IDs": {
            "cwe": "CWE-330",
            "owasp": "A07:2021 - Identification and Authentication Failures",
            "description": "IDs de sessão previsíveis",
            "locations": ["vulnerabilities/weak_id/"]
        },
        "Brute Force": {
            "cwe": "CWE-307",
            "owasp": "A07:2021 - Identification and Authentication Failures",
            "description": "Ausência de proteção contra força bruta",
            "locations": ["vulnerabilities/brute/"]
        },
        "Insecure CAPTCHA": {
            "cwe": "CWE-804",
            "owasp": "A07:2021 - Identification and Authentication Failures",
            "description": "CAPTCHA facilmente burlável",
            "locations": ["vulnerabilities/captcha/"]
        },
        "Open HTTP Redirect": {
            "cwe": "CWE-601",
            "owasp": "A01:2021 - Broken Access Control",
            "description": "Redirecionamento aberto para sites maliciosos",
            "locations": ["vulnerabilities/open_redirect/"]
        },
        "JavaScript Attacks": {
            "cwe": "CWE-749",
            "owasp": "A05:2021 - Security Misconfiguration",
            "description": "Exposição de lógica sensível no cliente",
            "locations": ["vulnerabilities/javascript/"]
        },
        "Content Security Policy Bypass": {
            "cwe": "CWE-693",
            "owasp": "A05:2021 - Security Misconfiguration",
            "description": "Ausência ou bypass de CSP",
            "locations": ["vulnerabilities/csp/"]
        },
        "Authorisation Bypass": {
            "cwe": "CWE-639",
            "owasp": "A01:2021 - Broken Access Control",
            "description": "Bypass de controles de autorização",
            "locations": ["vulnerabilities/authbypass/"]
        }
    },
    "infrastructure": {
        "Outdated OS": {
            "cwe": "CWE-1104",
            "description": "Sistema operacional desatualizado (Debian 9.5 EOSL)",
            "severity": "CRITICAL"
        },
        "Outdated Packages": {
            "cwe": "CWE-1104", 
            "description": "Pacotes com vulnerabilidades conhecidas",
            "severity": "HIGH"
        },
        "Default Credentials": {
            "cwe": "CWE-798",
            "description": "Credenciais padrão (admin/password)",
            "severity": "CRITICAL"
        },
        "Exposed MySQL": {
            "cwe": "CWE-284",
            "description": "MySQL com credenciais fracas",
            "severity": "HIGH"
        }
    }
}


def find_report_file(base_name):
    """
    Encontra o arquivo de relatório mais recente, com ou sem prefixo.
    
    O pipeline Cloud Build salva os relatórios com prefixo 'reports-{SHORT_SHA}_'
    Exemplo: reports-67e4d2f_semgrep-report.json
    
    Esta função busca:
    1. Primeiro, arquivos com prefixo 'reports-*_' + base_name (mais recente)
    2. Se não encontrar, busca o arquivo sem prefixo
    
    Args:
        base_name: Nome base do arquivo (ex: 'semgrep-report.json')
    
    Returns:
        Caminho do arquivo encontrado ou None
    """
    import glob
    
    # Buscar arquivos com prefixo reports-*_
    pattern = f"reports-*_{base_name}"
    matches = glob.glob(pattern)
    
    if matches:
        # Se houver múltiplos, pegar o mais recente (por data de modificação)
        matches.sort(key=os.path.getmtime, reverse=True)
        print(f"[INFO] Usando relatório: {matches[0]}")
        return matches[0]
    
    # Se não encontrar com prefixo, tentar sem prefixo
    if os.path.exists(base_name):
        print(f"[INFO] Usando relatório: {base_name}")
        return base_name
    
    # Também tentar em subpastas reports-*/
    subdir_pattern = f"reports-*/{base_name}"
    subdir_matches = glob.glob(subdir_pattern)
    if subdir_matches:
        subdir_matches.sort(key=os.path.getmtime, reverse=True)
        print(f"[INFO] Usando relatório: {subdir_matches[0]}")
        return subdir_matches[0]
    
    print(f"[AVISO] Relatório não encontrado: {base_name}")
    return None


def load_json(filepath):
    """Carrega arquivo JSON"""
    # Se for um nome base, tentar encontrar o arquivo com prefixo
    if filepath and not os.path.exists(filepath):
        found_path = find_report_file(filepath)
        if found_path:
            filepath = found_path
    
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"[AVISO] Não foi possível carregar {filepath}: {e}")
        return None


# ============================================================================
# VALIDAÇÃO DE COBERTURA DO ZAP
# ============================================================================

# URLs vulneráveis esperadas no DVWA que o ZAP deveria testar
DVWA_VULNERABLE_URLS = [
    "/vulnerabilities/sqli/",
    "/vulnerabilities/sqli_blind/",
    "/vulnerabilities/xss_r/",
    "/vulnerabilities/xss_s/",
    "/vulnerabilities/xss_d/",
    "/vulnerabilities/exec/",
    "/vulnerabilities/fi/",
    "/vulnerabilities/upload/",
    "/vulnerabilities/csrf/",
    "/vulnerabilities/brute/",
    "/vulnerabilities/captcha/",
    "/vulnerabilities/weak_id/",
]

# CWEs que o ZAP Active Scan deveria detectar no DVWA em nível LOW
EXPECTED_ZAP_CWES = {
    89: {"name": "SQL Injection", "required": True, "urls": ["/sqli/", "/sqli_blind/"]},
    79: {"name": "Cross-Site Scripting (XSS)", "required": True, "urls": ["/xss_r/", "/xss_s/", "/xss_d/"]},
    78: {"name": "OS Command Injection", "required": True, "urls": ["/exec/"]},
    22: {"name": "Path Traversal", "required": False, "urls": ["/fi/"]},
    98: {"name": "Improper Control of Filename for Include", "required": False, "urls": ["/fi/"]},
    352: {"name": "Cross-Site Request Forgery (CSRF)", "required": False, "urls": ["/csrf/"]},
}


def validate_zap_coverage(zap_report_path):
    """
    Valida se o ZAP está testando as URLs vulneráveis do DVWA
    e detectando as vulnerabilidades esperadas.
    
    Retorna um dicionário com:
    - urls_tested: URLs do DVWA que foram testadas
    - urls_missing: URLs do DVWA que não foram testadas
    - cwes_detected: CWEs detectados
    - cwes_missing: CWEs esperados mas não detectados
    - coverage_score: Percentual de cobertura
    - issues: Lista de problemas identificados
    """
    result = {
        "urls_tested": [],
        "urls_missing": [],
        "cwes_detected": [],
        "cwes_missing": [],
        "coverage_score": 0,
        "issues": [],
        "recommendations": [],
        "timeout": False
    }
    
    data = load_json(zap_report_path)
    if not data:
        result["issues"].append("Relatório ZAP não encontrado ou inválido")
        return result
    
    if "error" in data:
        result["issues"].append(f"ZAP retornou erro: {data['error']}")
        return result
    
    # Verificar se houve timeout no Active Scan
    if data.get("timeout", False):
        result["timeout"] = True
        result["issues"].append("⏱️ TIMEOUT: O Active Scan não completou em 10 minutos. Os resultados são parciais.")
        result["recommendations"].append("Considerar aumentar o timeout ou executar o scan localmente para resultados completos")
    
    # Extrair URLs testadas dos alertas
    tested_urls = set()
    detected_cwes = set()
    
    # Formato da API REST: {"alerts": [...]}
    alerts = data.get("alerts", [])
    if not alerts:
        # Tentar formato do report HTML/JSON tradicional
        for site in data.get("site", []):
            for alert in site.get("alerts", []):
                for instance in alert.get("instances", []):
                    url = instance.get("uri", "")
                    if url:
                        tested_urls.add(url)
                cwe = alert.get("cweid", "")
                if cwe:
                    detected_cwes.add(int(cwe))
    else:
        for alert in alerts:
            url = alert.get("url", "")
            if url:
                tested_urls.add(url)
            cwe = alert.get("cweid", "")
            if cwe:
                try:
                    detected_cwes.add(int(cwe))
                except ValueError:
                    pass
    
    # Verificar quais URLs vulneráveis foram testadas
    for vuln_url in DVWA_VULNERABLE_URLS:
        found = any(vuln_url in url for url in tested_urls)
        if found:
            result["urls_tested"].append(vuln_url)
        else:
            result["urls_missing"].append(vuln_url)
    
    # Verificar CWEs detectados vs esperados
    for cwe_id, cwe_info in EXPECTED_ZAP_CWES.items():
        if cwe_id in detected_cwes:
            result["cwes_detected"].append({
                "cwe": f"CWE-{cwe_id}",
                "name": cwe_info["name"],
                "required": cwe_info["required"]
            })
        else:
            result["cwes_missing"].append({
                "cwe": f"CWE-{cwe_id}",
                "name": cwe_info["name"],
                "required": cwe_info["required"],
                "expected_urls": cwe_info["urls"]
            })
    
    # Calcular score de cobertura
    total_expected = len(EXPECTED_ZAP_CWES)
    total_detected = len(result["cwes_detected"])
    result["coverage_score"] = (total_detected / total_expected * 100) if total_expected > 0 else 0
    
    # ===================================================================
    # DIAGNÓSTICO: Verificar se plugins de ataque foram executados
    # ===================================================================
    # Plugins de Active Scan para injeção começam com 40xxx ou 90xxx
    INJECTION_PLUGINS = {
        "40018": "SQL Injection",
        "40019": "SQL Injection (MySQL)",
        "40020": "SQL Injection (Hypersonic)",
        "40021": "SQL Injection (Oracle)",
        "40022": "SQL Injection (PostgreSQL)",
        "40024": "SQL Injection (SQLite)",
        "40012": "XSS (Reflected)",
        "40014": "XSS (Persistent)",
        "90019": "Server Side Code Injection",
        "90020": "Remote OS Command Injection",
    }
    
    # Verificar quais plugins foram executados baseado nos alertas
    plugin_ids_found = set()
    for alert in alerts:
        pid = alert.get("pluginId", "")
        if pid:
            plugin_ids_found.add(str(pid))
    
    injection_plugins_executed = [
        (pid, name) for pid, name in INJECTION_PLUGINS.items() 
        if pid in plugin_ids_found
    ]
    
    result["injection_plugins_executed"] = injection_plugins_executed
    result["all_plugins_found"] = list(plugin_ids_found)
    
    # Se nenhum plugin de injeção foi executado, há um problema de configuração
    if not injection_plugins_executed:
        result["issues"].append(
            "⚠️ DIAGNÓSTICO: Nenhum plugin de ataque de injeção (SQLi/XSS/Command Injection) foi executado. "
            "Isso indica que o Active Scan pode não ter rodado corretamente ou não teve acesso autenticado às páginas vulneráveis."
        )
        result["recommendations"].append(
            "Configurar o ZAP com sessão HTTP autenticada usando o cookie PHPSESSID"
        )
        result["recommendations"].append(
            "Usar a API 'replacer' do ZAP para injetar cookies em todas as requisições"
        )
        result["recommendations"].append(
            "Verificar logs do ZAP para confirmar que o Active Scan iniciou (plugins 40018, 40012, 90020)"
        )
    
    # Identificar problemas adicionais
    required_missing = [c for c in result["cwes_missing"] if c["required"]]
    if required_missing:
        result["issues"].append(
            f"Vulnerabilidades críticas não detectadas: {', '.join(c['name'] for c in required_missing)}"
        )
        result["recommendations"].append(
            "Verificar se o DVWA está configurado em nível 'Low'"
        )
        result["recommendations"].append(
            "Verificar se o ZAP está autenticando corretamente no DVWA"
        )
    
    if result["urls_missing"]:
        result["issues"].append(
            f"{len(result['urls_missing'])} URLs vulneráveis não foram testadas"
        )
        result["recommendations"].append(
            "Verificar se o Spider está alcançando todas as páginas"
        )
    
    return result


def detect_analysis_limitations():
    """
    Detecta dinamicamente as limitações da análise baseado nos arquivos disponíveis.
    
    Retorna um dicionário com limitações identificadas por ferramenta.
    """
    limitations = {
        "sast": [],
        "sca": [],
        "dast": [],
        "iac": [],
        "container": [],
        "bruteforce": []
    }
    
    # Verificar se há código-fonte PHP para SAST
    dvwa_src_path = Path(__file__).parent.parent / "Codigos" / "DevSecOps" / "dvwa" / "src"
    if not dvwa_src_path.exists():
        limitations["sast"].append({
            "issue": "Código-fonte do DVWA não está presente no repositório",
            "impact": "Semgrep não pode analisar o código PHP da aplicação",
            "recommendation": "Clonar o código-fonte do DVWA para dvwa/src/"
        })
    else:
        # Verificar se tem arquivos PHP
        php_files = list(dvwa_src_path.glob("**/*.php"))
        if len(php_files) == 0:
            limitations["sast"].append({
                "issue": "Nenhum arquivo PHP encontrado no código-fonte",
                "impact": "Análise SAST será limitada",
                "recommendation": "Verificar se o DVWA foi clonado corretamente"
            })
    
    # Verificar relatório Semgrep
    semgrep_data = load_json("semgrep-report.json")
    if semgrep_data:
        findings_count = len(semgrep_data.get("results", []))
        if findings_count == 0:
            limitations["sast"].append({
                "issue": "Semgrep não encontrou vulnerabilidades",
                "impact": "Pode indicar falta de código para analisar ou regras inadequadas",
                "recommendation": "Verificar se o Semgrep está apontando para o código-fonte correto"
            })
    
    # Verificar relatório Trivy SCA
    trivy_sca_data = load_json("trivy-sca-report.json")
    if trivy_sca_data:
        results = trivy_sca_data.get("Results", [])
        total_vulns = sum(len(r.get("Vulnerabilities", [])) for r in results)
        if total_vulns == 0:
            limitations["sca"].append({
                "issue": "Trivy SCA não encontrou vulnerabilidades em dependências",
                "impact": "Pode indicar ausência de arquivos de dependência (composer.json, etc.)",
                "recommendation": "Verificar se o Trivy está analisando o diretório correto com dependências"
            })
    
    # Verificar relatórios ZAP
    zap_baseline = load_json("zap-report.json")
    zap_active = load_json("zap-auth-active-report.json")
    
    if zap_baseline and "error" in zap_baseline:
        limitations["dast"].append({
            "issue": f"ZAP Baseline falhou: {zap_baseline['error']}",
            "impact": "Sem análise de segurança dinâmica básica",
            "recommendation": "Verificar conectividade e disponibilidade do DVWA"
        })
    
    if zap_active:
        if "error" in zap_active:
            limitations["dast"].append({
                "issue": f"ZAP Active Scan falhou: {zap_active['error']}",
                "impact": "Sem detecção de SQLi, XSS e outras vulnerabilidades de injeção",
                "recommendation": "Verificar autenticação e configuração do ZAP"
            })
        else:
            # Validar cobertura
            coverage = validate_zap_coverage("zap-auth-active-report.json")
            if coverage["coverage_score"] < 50:
                limitations["dast"].append({
                    "issue": f"Cobertura do ZAP Active Scan baixa ({coverage['coverage_score']:.1f}%)",
                    "impact": "Muitas vulnerabilidades conhecidas do DVWA não foram detectadas",
                    "recommendation": "; ".join(coverage["recommendations"]) if coverage["recommendations"] else "Revisar configuração do ZAP"
                })
    else:
        limitations["dast"].append({
            "issue": "Relatório do ZAP Active Scan não encontrado",
            "impact": "Sem detecção ativa de vulnerabilidades web",
            "recommendation": "Verificar se o step zap-auth-active-scan foi executado"
        })
    
    # Verificar Checkov
    checkov_data = load_json("checkov-report.json")
    if not checkov_data:
        limitations["iac"].append({
            "issue": "Relatório Checkov não encontrado",
            "impact": "Sem análise de segurança de IaC (Terraform/Kubernetes)",
            "recommendation": "Verificar se o Checkov foi executado corretamente"
        })
    
    # Verificar Brute Force
    hydra_data = load_json("hydra-bruteforce.json")
    if hydra_data and "error" in hydra_data:
        limitations["bruteforce"].append({
            "issue": f"Teste de brute force falhou: {hydra_data['error']}",
            "impact": "Não foi possível testar resistência a ataques de força bruta",
            "recommendation": "Verificar conectividade e script de brute force"
        })
    
    return limitations


def analyze_trivy_container():
    """Analisa relatório do Trivy Container Scan"""
    data = load_json('trivy-report.json')
    if not data:
        return None
    
    analysis = {
        'tool': 'Trivy',
        'type': 'Container Scan',
        'target': data.get('ArtifactName', 'N/A'),
        'os': f"{data.get('Metadata', {}).get('OS', {}).get('Family', '')} {data.get('Metadata', {}).get('OS', {}).get('Name', '')}",
        'eosl': data.get('Metadata', {}).get('OS', {}).get('EOSL', False),
        'vulnerabilities': [],
        'by_severity': defaultdict(int),
        'by_package': defaultdict(list),
        'by_cwe': defaultdict(int),
        'critical_cves': []
    }
    
    for result in data.get('Results', []):
        for vuln in result.get('Vulnerabilities', []):
            v = {
                'id': vuln.get('VulnerabilityID', 'N/A'),
                'package': vuln.get('PkgName', 'N/A'),
                'version': vuln.get('InstalledVersion', 'N/A'),
                'fixed_version': vuln.get('FixedVersion', 'N/A'),
                'severity': vuln.get('Severity', 'UNKNOWN'),
                'title': vuln.get('Title', ''),
                'description': vuln.get('Description', '')[:200] if vuln.get('Description') else '',
                'cvss': vuln.get('CVSS', {})
            }
            
            analysis['vulnerabilities'].append(v)
            analysis['by_severity'][v['severity']] += 1
            analysis['by_package'][v['package']].append(v['id'])
            
            # Extrair CWE se disponível
            for cwe in vuln.get('CweIDs', []):
                analysis['by_cwe'][cwe] += 1
            
            if v['severity'] == 'CRITICAL':
                analysis['critical_cves'].append(v)
    
    return analysis


def analyze_semgrep():
    """Analisa relatório do Semgrep SAST"""
    data = load_json('semgrep-report.json')
    if not data:
        return None
    
    analysis = {
        'tool': 'Semgrep',
        'type': 'SAST (Static Application Security Testing)',
        'findings': [],
        'by_severity': defaultdict(int),
        'by_file': defaultdict(list),
        'by_cwe': defaultdict(int),
        'by_owasp': defaultdict(int),
        'by_rule': defaultdict(int)
    }
    
    for result in data.get('results', []):
        extra = result.get('extra', {})
        metadata = extra.get('metadata', {})
        
        finding = {
            'rule_id': result.get('check_id', 'N/A'),
            'rule_name': result.get('check_id', '').split('.')[-1],
            'file': result.get('path', 'N/A'),
            'line': result.get('start', {}).get('line', '?'),
            'severity': extra.get('severity', 'UNKNOWN'),
            'message': extra.get('message', '')[:300] if extra.get('message') else '',
            'fix': extra.get('fix', ''),
            'cwe': metadata.get('cwe', []),
            'owasp': metadata.get('owasp', []),
            'category': metadata.get('category', 'N/A')
        }
        
        analysis['findings'].append(finding)
        analysis['by_severity'][finding['severity']] += 1
        analysis['by_file'][finding['file']].append(finding)
        analysis['by_rule'][finding['rule_name']] += 1
        
        for cwe in finding['cwe']:
            analysis['by_cwe'][cwe] += 1
        for owasp in finding['owasp']:
            analysis['by_owasp'][owasp] += 1
    
    return analysis


def analyze_trivy_sca():
    """Analisa relatório do Trivy SCA (Software Composition Analysis)"""
    data = load_json('trivy-sca-report.json')
    if not data:
        return None
    
    analysis = {
        'tool': 'Trivy',
        'type': 'SCA (Software Composition Analysis)',
        'target': data.get('ArtifactName', '.'),
        'vulnerabilities': [],
        'by_severity': defaultdict(int)
    }
    
    for result in data.get('Results', []):
        for vuln in result.get('Vulnerabilities', []):
            v = {
                'id': vuln.get('VulnerabilityID', 'N/A'),
                'package': vuln.get('PkgName', 'N/A'),
                'severity': vuln.get('Severity', 'UNKNOWN')
            }
            analysis['vulnerabilities'].append(v)
            analysis['by_severity'][v['severity']] += 1
    
    return analysis


def analyze_zap():
    """Analisa relatório do OWASP ZAP DAST"""
    data = load_json('zap-report.json')
    if not data:
        return None
    
    # Verificar se é erro
    if 'error' in data:
        return {'error': data['error']}
    
    analysis = {
        'tool': 'OWASP ZAP',
        'type': 'DAST (Dynamic Application Security Testing)',
        'alerts': [],
        'by_risk': defaultdict(int),
        'by_cwe': defaultdict(int),
        'target': ''
    }
    
    # Formato do ZAP pode variar e pode ter múltiplos sites
    sites = data.get('site', [])
    if not isinstance(sites, list):
        sites = [sites] if sites else []
    
    # Coletar alertas de TODOS os sites
    all_alerts = []
    for site in sites:
        if not isinstance(site, dict):
            continue
        # Guardar o primeiro target encontrado
        if not analysis['target']:
            analysis['target'] = site.get('@name', 'N/A')
        
        site_alerts = site.get('alerts', [])
        if isinstance(site_alerts, dict):
            site_alerts = site_alerts.get('alertitem', [])
        if not isinstance(site_alerts, list):
            site_alerts = [site_alerts] if site_alerts else []
        all_alerts.extend(site_alerts)
    
    # Se não encontrou em site, tentar na raiz
    if not all_alerts:
        all_alerts = data.get('alerts', [])
        if isinstance(all_alerts, dict):
            all_alerts = all_alerts.get('alertitem', [])
        if not isinstance(all_alerts, list):
            all_alerts = [all_alerts] if all_alerts else []
    
    for alert in all_alerts:
        if not alert:
            continue
        a = {
            'name': alert.get('name', alert.get('alert', 'N/A')),
            'risk': alert.get('riskdesc', alert.get('risk', 'N/A')),
            'confidence': alert.get('confidence', 'N/A'),
            'description': alert.get('desc', '')[:200] if alert.get('desc') else '',
            'solution': alert.get('solution', ''),
            'cwe': alert.get('cweid', ''),
            'wasc': alert.get('wascid', ''),
            'count': len(alert.get('instances', [])) if alert.get('instances') else int(alert.get('count', 1))
        }
        
        analysis['alerts'].append(a)
        
        # Mapear risk level
        risk_level = a['risk'].split()[0] if a['risk'] else 'Informational'
        analysis['by_risk'][risk_level] += 1
        
        if a['cwe']:
            analysis['by_cwe'][f"CWE-{a['cwe']}"] += 1
    
    return analysis


def analyze_zap_active():
    """Analisa relatório do OWASP ZAP Active Scan (autenticado)"""
    data = load_json('zap-auth-active-report.json')
    if not data:
        return None
    
    # Verificar se é erro
    if 'error' in data:
        return {'error': data['error']}
    
    analysis = {
        'tool': 'OWASP ZAP',
        'type': 'DAST Active Scan (Authenticated)',
        'alerts': [],
        'by_risk': defaultdict(int),
        'by_cwe': defaultdict(int),
        'target': ''
    }
    
    # O formato da API REST é diferente: {"alerts": [...]}
    alerts = data.get('alerts', [])
    if not isinstance(alerts, list):
        alerts = [alerts] if alerts else []
    
    # Agrupar alertas únicos por nome
    unique_alerts = {}
    for alert in alerts:
        if not alert:
            continue
        name = alert.get('name', alert.get('alert', 'N/A'))
        if name not in unique_alerts:
            unique_alerts[name] = {
                'name': name,
                'risk': alert.get('risk', 'Informational'),
                'confidence': alert.get('confidence', 'N/A'),
                'description': alert.get('description', '')[:200] if alert.get('description') else '',
                'solution': alert.get('solution', ''),
                'cwe': alert.get('cweid', ''),
                'wasc': alert.get('wascid', ''),
                'count': 1,
                'urls': [alert.get('url', '')]
            }
            if not analysis['target'] and alert.get('url'):
                # Extrair host da URL
                url = alert.get('url', '')
                if url:
                    parts = url.split('/')
                    if len(parts) >= 3:
                        analysis['target'] = '/'.join(parts[:3])
        else:
            unique_alerts[name]['count'] += 1
            if alert.get('url'):
                unique_alerts[name]['urls'].append(alert.get('url', ''))
    
    for alert in unique_alerts.values():
        analysis['alerts'].append(alert)
        
        # Mapear risk level
        risk_map = {'High': 'High', 'Medium': 'Medium', 'Low': 'Low', 'Informational': 'Informational'}
        risk_level = risk_map.get(alert['risk'], 'Informational')
        analysis['by_risk'][risk_level] += 1
        
        if alert['cwe']:
            analysis['by_cwe'][f"CWE-{alert['cwe']}"] += 1
    
    return analysis


def analyze_hydra_bruteforce():
    """Analisa relatório do Brute Force (Hydra ou script customizado)"""
    data = load_json('hydra-bruteforce.json')
    if not data:
        return None
    
    analysis = {
        'tool': data.get('tool', 'Brute Force Scanner'),
        'type': 'Brute Force',
        'vulnerable': False,
        'credentials_found': [],
        'total_attempts': 0,
        'csrf_token_required': False,
        'details': []
    }
    
    # Novo formato do script customizado
    if 'successful_logins' in data:
        analysis['credentials_found'] = data.get('successful_logins', [])
        analysis['total_attempts'] = data.get('total_attempts', 0)
        analysis['csrf_token_required'] = data.get('csrf_token_required', False)
        analysis['vulnerable'] = data.get('vulnerable', False)
        analysis['details'] = data.get('details', [])
        
        if analysis['credentials_found']:
            analysis['result'] = f"VULNERÁVEL: {len(analysis['credentials_found'])} credenciais fracas encontradas"
        else:
            analysis['result'] = f"Nenhuma credencial fraca encontrada em {analysis['total_attempts']} tentativas"
    
    # Formato antigo do Hydra (compatibilidade)
    elif 'results' in data:
        result = data.get('results', '')
        analysis['result'] = result
        if result and 'Nenhuma credencial encontrada' not in result and 'erro' not in result.lower():
            analysis['vulnerable'] = True
    
    # Erro de IP não disponível
    elif 'error' in data:
        analysis['result'] = data.get('error', 'Erro desconhecido')
        analysis['vulnerable'] = False
    
    return analysis


def analyze_checkov():
    """Analisa relatório do Checkov IaC Scan"""
    data = load_json('checkov-report.json')
    if not data:
        return None
    
    analysis = {
        'tool': 'Checkov',
        'type': 'IaC Security Scan',
        'passed': 0,
        'failed': 0,
        'skipped': 0,
        'findings': [],
        'by_severity': defaultdict(int),
        'by_check_type': defaultdict(int)
    }
    
    # Checkov pode ter formato combinado (terraform + kubernetes)
    if 'terraform' in data:
        for check_type in ['terraform', 'kubernetes']:
            if check_type in data:
                sub_data = data[check_type]
                _process_checkov_results(sub_data, analysis, check_type)
    else:
        _process_checkov_results(data, analysis, 'iac')
    
    return analysis


def _process_checkov_results(data, analysis, check_type):
    """Processa resultados do Checkov"""
    if isinstance(data, list):
        for item in data:
            _process_checkov_results(item, analysis, check_type)
        return
    
    if not isinstance(data, dict):
        return
    
    summary = data.get('summary', {})
    analysis['passed'] += summary.get('passed', 0)
    analysis['failed'] += summary.get('failed', 0)
    analysis['skipped'] += summary.get('skipped', 0)
    
    for result in data.get('results', {}).get('failed_checks', []):
        finding = {
            'check_id': result.get('check_id', 'N/A'),
            'check_name': result.get('check', {}).get('name', result.get('check_id', 'N/A')),
            'file': result.get('file_path', 'N/A'),
            'resource': result.get('resource', 'N/A'),
            'severity': result.get('severity', 'MEDIUM'),
            'guideline': result.get('guideline', ''),
            'check_type': check_type
        }
        analysis['findings'].append(finding)
        analysis['by_severity'][finding['severity']] += 1
        analysis['by_check_type'][check_type] += 1


def compare_with_known_vulnerabilities(trivy_analysis, semgrep_analysis, zap_analysis, hydra_analysis=None, zap_active_analysis=None):
    """Compara vulnerabilidades encontradas com as conhecidas do DVWA"""
    
    coverage = {
        'detected': [],
        'not_detected': [],
        'additional_findings': []
    }

    # CWEs encontrados pelas ferramentas
    detected_cwes = set()
    cwe_to_tool = {}

    # Trivy Container
    if trivy_analysis:
        for cwe in trivy_analysis['by_cwe'].keys():
            detected_cwes.add(cwe)
            cwe_to_tool[cwe] = 'Trivy (Container)'

    # Trivy SCA - Não traz CWE por padrão, mas pode ser extendido se necessário
    # A análise SCA é feita separadamente em analyze_trivy_sca()

    # Semgrep
    if semgrep_analysis:
        for f in semgrep_analysis['findings']:
            for cwe in f.get('cwe', []):
                if 'CWE-' in cwe:
                    norm_cwe = cwe.split(':')[0] if ':' in cwe else cwe
                    detected_cwes.add(norm_cwe)
                    cwe_to_tool[norm_cwe] = 'Semgrep'

    # ZAP Baseline
    if zap_analysis and 'by_cwe' in zap_analysis:
        for cwe in zap_analysis['by_cwe'].keys():
            detected_cwes.add(cwe)
            cwe_to_tool[cwe] = 'OWASP ZAP (Baseline)'

    # ZAP Active Scan (autenticado) - Este pode detectar SQLi, XSS, etc.
    if zap_active_analysis and 'by_cwe' in zap_active_analysis:
        for cwe in zap_active_analysis['by_cwe'].keys():
            detected_cwes.add(cwe)
            cwe_to_tool[cwe] = 'OWASP ZAP (Active Scan)'

    # Checkov - check_id geralmente não é CWE, então não adicionamos aqui
    # O Checkov detecta problemas de IaC, não vulnerabilidades de aplicação web
    
    # Hydra - Brute Force
    # Se o Hydra foi executado (mesmo sem encontrar vuln), considerar CWE-307 (Brute Force) como testado
    hydra_tested = False
    hydra_vulnerable = False
    if hydra_analysis:
        hydra_tested = True
        hydra_vulnerable = hydra_analysis.get('vulnerable', False)
        if hydra_vulnerable:
            # Se Hydra encontrou credenciais fracas, detectou CWE-307 e CWE-798
            detected_cwes.add('CWE-307')  # Brute Force
            detected_cwes.add('CWE-798')  # Default Credentials
            cwe_to_tool['CWE-307'] = 'Hydra'
            cwe_to_tool['CWE-798'] = 'Hydra'
    
    # Trivy EOSL - Se detectou sistema operacional em End of Support Life
    if trivy_analysis and trivy_analysis.get('eosl', False):
        detected_cwes.add('CWE-1104')  # Outdated OS/Packages
        cwe_to_tool['CWE-1104'] = 'Trivy (Container - EOSL)'
    
    # Verificar cobertura das vulnerabilidades conhecidas
    for category, vulns in DVWA_KNOWN_VULNERABILITIES.items():
        for vuln_name, vuln_info in vulns.items():
            cwe = vuln_info.get('cwe', '')
            detected = cwe in detected_cwes
            entry = {
                'name': vuln_name,
                'category': category,
                'cwe': cwe,
                'owasp': vuln_info.get('owasp', 'N/A'),
                'description': vuln_info.get('description', '')
            }
            if detected:
                entry['ferramenta'] = cwe_to_tool.get(cwe, '-')
                coverage['detected'].append(entry)
            else:
                entry['ferramenta'] = '-'
                coverage['not_detected'].append(entry)

    # Preencher motivo, sugestao e ferramenta para todos os itens
    def motivo_sugestao(vuln):
        cwe = vuln.get('cwe', '')
        name = vuln.get('name', '')
        category = vuln.get('category', '')
        # Infraestrutura
        if category == 'infrastructure':
            if name == 'Outdated OS':
                return ("Só detectável se o scanner identificar o SO base como EOL.", "Verifique se o Trivy está analisando o SO base corretamente.", "Trivy")
            if name == 'Outdated Packages':
                return ("Só detectável se o scanner identificar pacotes desatualizados.", "Verifique se o Trivy está analisando todos os pacotes.", "Trivy")
            if name == 'Default Credentials':
                return ("Requer brute force/login automatizado.", "Adicionar brute force (ex: hydra) na pipeline.", "-")
            if name == 'Exposed MySQL':
                return ("Só detectável se o scanner identificar exposição de serviço e credenciais fracas.", "Verifique se há testes de exposição de porta e credenciais.", "Trivy")
            return ("Não detectável por SAST/SCA/IaC.", "-", "-")
        # Web application
        if name == 'File Inclusion (LFI/RFI)':
            return ("Requer autenticação e/ou ataque ativo.", "Adicionar ZAP autenticado/active scan na pipeline.", "-")
        if name == 'File Upload':
            return ("Requer autenticação e/ou ataque ativo.", "Adicionar ZAP autenticado/active scan na pipeline.", "-")
        if name == 'Brute Force':
            return ("Requer brute force/login automatizado.", "Adicionar brute force (ex: hydra) na pipeline.", "-")
        if name == 'Insecure CAPTCHA':
            return ("Requer interação humana ou automação avançada.", "Fora do escopo do pipeline automatizado.", "-")
        if name == 'Authorisation Bypass':
            return ("Requer autenticação e/ou ataque ativo.", "Adicionar ZAP autenticado/active scan na pipeline.", "-")
        if name == 'CSRF':
            return ("Só detectável se o scanner simular ações autenticadas.", "Adicionar ZAP autenticado/active scan na pipeline.", "-")
        if name == 'Weak Session IDs':
            return ("Só detectável se o scanner analisar tokens de sessão.", "Adicionar análise de sessão no DAST.", "-")
        if name == 'SQL Injection':
            return ("Só detectável se o scanner executar payloads ativos.", "Adicionar active scan no ZAP.", "-")
        if name == 'Cross-Site Scripting (XSS)':
            return ("Só detectável se o scanner executar payloads ativos.", "Adicionar active scan no ZAP.", "-")
        if name == 'Command Injection':
            return ("Só detectável se o scanner executar payloads ativos.", "Adicionar active scan no ZAP.", "-")
        if name == 'JavaScript Attacks':
            return ("Requer SAST para JS/PHP.", "Adicionar SAST específico para PHP/JS.", "-")
        if name == 'Content Security Policy Bypass':
            return ("Pode ser detectado por DAST, mas depende da regra e contexto.", "Verificar configuração do ZAP para CSP.", "-")
        if name == 'Open HTTP Redirect':
            return ("Só detectável se o scanner seguir e analisar redirects.", "Verificar se o DAST cobre redirects.", "-")
        return ("Cobertura limitada pelo tipo de teste atual.", "Analisar possibilidade de ajuste na pipeline.", "-")

    # Atualiza todos os itens com motivo/sugestao/ferramenta
    for entry in coverage['detected']:
        entry['motivo'] = "Detectada pelo pipeline."
        entry['sugestao'] = "-"
        # ferramenta já preenchida
    for entry in coverage['not_detected']:
        motivo, sugestao, ferramenta = motivo_sugestao(entry)
        entry['motivo'] = motivo
        entry['sugestao'] = sugestao
        entry['ferramenta'] = ferramenta if ferramenta != '-' else entry.get('ferramenta', '-')
    return coverage


class MarkdownReport:
    """Gera relatório em formato Markdown"""
    
    def __init__(self):
        self.lines = []
    
    def add(self, text=""):
        self.lines.append(text)
    
    def add_header(self, title, level=1):
        self.add(f"{'#' * level} {title}")
        self.add()
    
    def add_table(self, headers, rows):
        """Adiciona tabela markdown"""
        self.add("| " + " | ".join(headers) + " |")
        self.add("| " + " | ".join(["---"] * len(headers)) + " |")
        for row in rows:
            self.add("| " + " | ".join(str(cell) for cell in row) + " |")
        self.add()
    
    def add_code_block(self, code, lang=""):
        self.add(f"```{lang}")
        self.add(code)
        self.add("```")
        self.add()
    
    def get_content(self):
        return "\n".join(self.lines)
    
    def save(self, filepath):
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(self.get_content())
        print(f"✅ Relatório salvo em: {filepath}")


def generate_report():
    """Gera relatório completo de análise em Markdown"""
    
    report = MarkdownReport()
    
    # Header
    report.add("# 📊 Análise Completa dos Relatórios de Segurança - Pipeline DevSecOps")
    report.add()
    report.add(f"**Data:** {datetime.now().strftime('%d/%m/%Y %H:%M')}")
    report.add()
    report.add("**Aplicação:** DVWA (Damn Vulnerable Web Application)")
    report.add()
    report.add("**Pesquisa:** Integração de Testes de Segurança Contínuos em Pipelines CI/CD")
    report.add()
    report.add("---")
    report.add()
    
    # Carregar análises
    trivy_container = analyze_trivy_container()
    semgrep = analyze_semgrep()
    trivy_sca = analyze_trivy_sca()
    zap = analyze_zap()
    zap_active = analyze_zap_active()  # ZAP Active Scan (autenticado)
    checkov = analyze_checkov()
    hydra = analyze_hydra_bruteforce()

    # Ajuste: só considerar como detectada vulnerabilidade do DVWA se o CWE foi encontrado em contexto relevante
    # Exemplo: CWE-89 só conta se foi detectado em findings do app, não só no container base
    # (Para simplificação, mantemos a lógica de CWE, mas pode ser refinada para contexto de findings)
    
    # ========================================================================
    # SUMÁRIO EXECUTIVO
    # ========================================================================
    report.add_header("📋 Sumário Executivo", 2)
    
    total_vulns = 0
    if trivy_container:
        total_vulns += len(trivy_container['vulnerabilities'])
    if semgrep:
        total_vulns += len(semgrep['findings'])
    if zap and 'alerts' in zap:
        total_vulns += len(zap['alerts'])
    if zap_active and 'alerts' in zap_active:
        total_vulns += len(zap_active['alerts'])
    if checkov:
        total_vulns += len(checkov['findings'])
    if hydra and hydra.get('vulnerable'):
        total_vulns += 1
    
    # Tabela resumo
    hydra_status = "✅ Executado" if hydra else "⚠️ Não disponível"
    hydra_result = "Vulnerável" if hydra and hydra.get('vulnerable') else ("Seguro" if hydra else "N/A")
    zap_active_status = "✅ Executado" if zap_active and 'alerts' in zap_active else "⚠️ Não disponível"
    zap_active_findings = len(zap_active['alerts']) if zap_active and 'alerts' in zap_active else 0
    report.add_table(
        ["Ferramenta", "Tipo", "Findings", "Status"],
        [
            ["Trivy", "Container Scan", len(trivy_container['vulnerabilities']) if trivy_container else 0, "✅ Executado"],
            ["Semgrep", "SAST", len(semgrep['findings']) if semgrep else 0, "✅ Executado"],
            ["Trivy FS", "SCA", len(trivy_sca['vulnerabilities']) if trivy_sca else 0, "✅ Executado"],
            ["OWASP ZAP", "DAST (Baseline)", len(zap['alerts']) if zap and 'alerts' in zap else 0, "✅ Executado" if zap and 'alerts' in zap else "⚠️ Não gerado"],
            ["OWASP ZAP", "DAST (Active Scan)", zap_active_findings, zap_active_status],
            ["Checkov", "IaC Scan", len(checkov['findings']) if checkov else 0, "✅ Executado" if checkov else "⚠️ Não disponível"],
            ["Hydra", "Brute Force", hydra_result, hydra_status]
        ]
    )
    
    report.add(f"**Total de issues de segurança identificados: {total_vulns}**")
    report.add()
    
    # ========================================================================
    # SEÇÃO 1: CONTAINER SCAN (TRIVY)
    # ========================================================================
    report.add_header("1. 📦 Container Scan - Trivy", 2)
    
    if trivy_container:
        report.add(f"**Imagem analisada:** `{trivy_container['target'].split('/')[-1]}`")
        report.add()
        report.add(f"**Sistema Operacional:** {trivy_container['os']}")
        report.add()
        report.add(f"**End of Support Life (EOSL):** {'⚠️ SIM - Sistema sem suporte!' if trivy_container['eosl'] else '✅ Não'}")
        report.add()
        
        report.add_header("Distribuição por Severidade", 3)
        total_cves = len(trivy_container['vulnerabilities'])
        if total_cves > 0:
            report.add_table(
                ["Severidade", "Quantidade", "Percentual"],
                [
                    ["🔴 CRITICAL", trivy_container['by_severity'].get('CRITICAL', 0), f"{trivy_container['by_severity'].get('CRITICAL', 0)/total_cves*100:.1f}%"],
                    ["🟠 HIGH", trivy_container['by_severity'].get('HIGH', 0), f"{trivy_container['by_severity'].get('HIGH', 0)/total_cves*100:.1f}%"],
                    ["🟡 MEDIUM", trivy_container['by_severity'].get('MEDIUM', 0), f"{trivy_container['by_severity'].get('MEDIUM', 0)/total_cves*100:.1f}%"],
                    ["🟢 LOW", trivy_container['by_severity'].get('LOW', 0), f"{trivy_container['by_severity'].get('LOW', 0)/total_cves*100:.1f}%"],
                ]
            )
        
        report.add_header("Top 10 Pacotes Mais Vulneráveis", 3)
        sorted_packages = sorted(trivy_container['by_package'].items(), key=lambda x: len(x[1]), reverse=True)[:10]
        report.add_table(
            ["#", "Pacote", "CVEs"],
            [[i, pkg, len(cves)] for i, (pkg, cves) in enumerate(sorted_packages, 1)]
        )
        
        report.add_header("Top 10 CWEs Mais Frequentes", 3)
        sorted_cwes = sorted(trivy_container['by_cwe'].items(), key=lambda x: x[1], reverse=True)[:10]
        report.add_table(
            ["CWE", "Ocorrências"],
            [[cwe, count] for cwe, count in sorted_cwes]
        )
        
        report.add_header("Exemplos de CVEs Críticas", 3)
        for i, cve in enumerate(trivy_container['critical_cves'][:5], 1):
            report.add(f"**{i}. {cve['id']}**")
            report.add(f"- Pacote: `{cve['package']}` v{cve['version']}")
            if cve['fixed_version']:
                report.add(f"- Correção: Atualizar para v{cve['fixed_version']}")
            if cve['title']:
                report.add(f"- Descrição: {cve['title'][:80]}...")
            report.add()
    else:
        report.add("⚠️ Relatório do Trivy Container não disponível.")
        report.add()
    
    # ========================================================================
    # SEÇÃO 2: SAST - SEMGREP
    # ========================================================================
    report.add_header("2. 🔍 SAST (Static Application Security Testing) - Semgrep", 2)
    
    if semgrep:
        report.add(f"**Total de findings:** {len(semgrep['findings'])}")
        report.add()
        
        report.add_header("Distribuição por Severidade", 3)
        report.add_table(
            ["Severidade", "Quantidade"],
            [
                ["🔴 ERROR", semgrep['by_severity'].get('ERROR', 0)],
                ["🟠 WARNING", semgrep['by_severity'].get('WARNING', 0)],
                ["🟢 INFO", semgrep['by_severity'].get('INFO', 0)],
            ]
        )
        
        report.add_header("Findings por Arquivo", 3)
        for filepath, findings in semgrep['by_file'].items():
            filename = filepath.split('/')[-1]
            report.add(f"**📄 {filename}**")
            report.add()
            for f in findings:
                severity_icon = {'ERROR': '🔴', 'WARNING': '🟠', 'INFO': '🟢'}.get(f['severity'], '⚪')
                report.add(f"- {severity_icon} **Linha {f['line']}:** `{f['rule_name']}`")
                report.add(f"  - CWE: {f['cwe'][0] if f['cwe'] else 'N/A'}")
                report.add(f"  - OWASP: {f['owasp'][0] if f['owasp'] else 'N/A'}")
            report.add()
        
        report.add_header("CWEs Identificados", 3)
        for cwe, count in semgrep['by_cwe'].items():
            report.add(f"- **{cwe}**: {count} ocorrência(s)")
        report.add()
        
        report.add_header("Mapeamento OWASP Top 10", 3)
        for owasp, count in semgrep['by_owasp'].items():
            report.add(f"- **{owasp}**: {count} ocorrência(s)")
        report.add()
    else:
        report.add("⚠️ Relatório do Semgrep não disponível.")
        report.add()
    
    # ========================================================================
    # SEÇÃO 3: SCA - TRIVY FS
    # ========================================================================
    report.add_header("3. 📦 SCA (Software Composition Analysis) - Trivy FS", 2)
    
    if trivy_sca:
        report.add(f"**Alvo:** Código fonte do projeto")
        report.add()
        report.add(f"**Vulnerabilidades em dependências:** {len(trivy_sca['vulnerabilities'])}")
        report.add()
        if len(trivy_sca['vulnerabilities']) == 0:
            report.add("✅ **NENHUMA VULNERABILIDADE CONHECIDA ENCONTRADA EM DEPENDÊNCIAS**")
            report.add()
            report.add("*Nota: Este resultado indica que as dependências declaradas (composer.lock, package-lock.json, etc.) não possuem CVEs conhecidas registradas nos bancos de dados de vulnerabilidades consultados pelo Trivy. Isso é um resultado positivo e válido.*")
        else:
            report.add("⚠️ Vulnerabilidades encontradas nas dependências")
        report.add()
    else:
        report.add("⚠️ Relatório do Trivy SCA não disponível.")
        report.add()
    
    # ========================================================================
    # SEÇÃO 4: DAST - OWASP ZAP
    # ========================================================================
    report.add_header("4. 🌐 DAST (Dynamic Application Security Testing) - OWASP ZAP", 2)
    
    if zap and 'alerts' in zap:
        report.add(f"**Alvo:** `{zap['target']}`")
        report.add()
        report.add(f"**Total de alertas:** {len(zap['alerts'])}")
        report.add()
        
        if zap['by_risk']:
            report.add_header("Distribuição por Risco", 3)
            risk_order = ['High', 'Medium', 'Low', 'Informational']
            sorted_risks = sorted(zap['by_risk'].items(), key=lambda x: risk_order.index(x[0]) if x[0] in risk_order else 99)
            report.add_table(
                ["Nível de Risco", "Quantidade"],
                [[risk, count] for risk, count in sorted_risks]
            )
        
        report.add_header("Alertas Encontrados", 3)
        for alert in zap['alerts']:
            risk_icon = {'High': '🔴', 'Medium': '🟠', 'Low': '🟡'}.get(alert['risk'].split()[0] if alert['risk'] else '', '🔵')
            report.add(f"**{risk_icon} {alert['name']}**")
            report.add(f"- Risco: {alert['risk']}")
            report.add(f"- CWE: CWE-{alert['cwe']}" if alert['cwe'] else "- CWE: N/A")
            if alert['description']:
                # Limpar HTML básico da descrição
                desc = alert['description'].replace('<p>', '').replace('</p>', ' ').replace('<br>', ' ')
                report.add(f"- Descrição: {desc[:100]}...")
            report.add()
        
        if zap['by_cwe']:
            report.add_header("CWEs Detectados pelo DAST", 3)
            for cwe, count in zap['by_cwe'].items():
                report.add(f"- **{cwe}**: {count} ocorrência(s)")
            report.add()
    elif zap and 'error' in zap:
        report.add(f"⚠️ **Erro na execução do ZAP:** {zap['error']}")
        report.add()
    else:
        report.add("⚠️ Relatório do OWASP ZAP não disponível.")
        report.add()
        report.add("**Possíveis causas:**")
        report.add("1. O ZAP não conseguiu acessar a aplicação")
        report.add("2. O LoadBalancer não obteve IP externo a tempo")
        report.add("3. A aplicação não estava pronta quando o scan iniciou")
        report.add()
    
    # ========================================================================
    # SEÇÃO 4.1: DAST - OWASP ZAP ACTIVE SCAN (AUTENTICADO)
    # ========================================================================
    report.add_header("4.1 🔓 DAST Active Scan (Autenticado) - OWASP ZAP", 2)
    
    if zap_active and 'alerts' in zap_active:
        report.add(f"**Alvo:** `{zap_active['target']}`")
        report.add()
        report.add(f"**Total de alertas:** {len(zap_active['alerts'])}")
        report.add()
        report.add("**Tipo de scan:** Active Scan com autenticação (detecta SQL Injection, XSS, etc.)")
        report.add()
        
        if zap_active['by_risk']:
            report.add_header("Distribuição por Risco", 3)
            risk_order = ['High', 'Medium', 'Low', 'Informational']
            sorted_risks = sorted(zap_active['by_risk'].items(), key=lambda x: risk_order.index(x[0]) if x[0] in risk_order else 99)
            report.add_table(
                ["Nível de Risco", "Quantidade"],
                [[risk, count] for risk, count in sorted_risks]
            )
        
        report.add_header("Alertas Encontrados (Active Scan)", 3)
        for alert in zap_active['alerts']:
            risk_icon = {'High': '🔴', 'Medium': '🟠', 'Low': '🟡'}.get(alert['risk'], '🔵')
            report.add(f"**{risk_icon} {alert['name']}** (x{alert['count']})")
            report.add(f"- Risco: {alert['risk']}")
            report.add(f"- CWE: CWE-{alert['cwe']}" if alert['cwe'] else "- CWE: N/A")
            if alert['description']:
                desc = alert['description'].replace('<p>', '').replace('</p>', ' ').replace('<br>', ' ')
                report.add(f"- Descrição: {desc[:100]}...")
            report.add()
        
        if zap_active['by_cwe']:
            report.add_header("CWEs Detectados pelo Active Scan", 3)
            for cwe, count in zap_active['by_cwe'].items():
                report.add(f"- **{cwe}**: {count} ocorrência(s)")
            report.add()
    elif zap_active and 'error' in zap_active:
        report.add(f"⚠️ **Erro na execução do ZAP Active Scan:** {zap_active['error']}")
        report.add()
    else:
        report.add("⚠️ Relatório do OWASP ZAP Active Scan não disponível.")
        report.add()
        report.add("**Possíveis causas:**")
        report.add("1. O scan autenticado não foi executado")
        report.add("2. Erro na autenticação com DVWA")
        report.add("3. O relatório zap-auth-active-report.json não foi gerado")
        report.add()
    
    # ========================================================================
    # SEÇÃO 5: IAC SCAN - CHECKOV
    # ========================================================================
    report.add_header("5. 🏗️ IaC Scan - Checkov", 2)
    
    if checkov:
        report.add(f"**Checks passados:** {checkov['passed']}")
        report.add()
        report.add(f"**Checks falhados:** {checkov['failed']}")
        report.add()
        report.add(f"**Checks ignorados:** {checkov['skipped']}")
        report.add()
        
        if checkov['findings']:
            report.add_header("Findings de Segurança", 3)
            report.add_table(
                ["Check ID", "Recurso", "Arquivo", "Severidade"],
                [[f['check_id'], f['resource'][:30] if f['resource'] else 'N/A', f['file'].split('/')[-1] if f['file'] else 'N/A', f['severity']] for f in checkov['findings'][:20]]
            )
        else:
            report.add("✅ **NENHUM PROBLEMA DE SEGURANÇA ENCONTRADO NO IaC!**")
        report.add()
    else:
        report.add("⚠️ Relatório do Checkov não disponível.")
        report.add()
    
    # ========================================================================
    # SEÇÃO 6: BRUTE FORCE - HYDRA
    # ========================================================================
    report.add_header("6. 🔐 Teste de Força Bruta - Hydra", 2)
    
    if hydra:
        report.add(f"**Ferramenta:** {hydra['tool']}")
        report.add()
        report.add(f"**Tipo de teste:** {hydra['type']}")
        report.add()
        if hydra.get('vulnerable'):
            report.add("### ⚠️ Vulnerabilidade Detectada!")
            report.add()
            report.add(f"**Resultado:** {hydra.get('result')}")
            report.add()
            report.add("A aplicação é vulnerável a ataques de força bruta. Credenciais fracas foram encontradas.")
        else:
            report.add("### ✅ Nenhuma Vulnerabilidade de Força Bruta Detectada")
            report.add()
            report.add(f"**Resultado:** {hydra.get('result')}")
            report.add()
            report.add("O teste de força bruta não encontrou credenciais fracas ou o teste não conseguiu ser executado com sucesso.")
        report.add()
    else:
        report.add("⚠️ Relatório do Hydra não disponível.")
        report.add()
    
    # ========================================================================
    # SEÇÃO 7: COMPARAÇÃO COM VULNERABILIDADES CONHECIDAS DO DVWA
    # ========================================================================
    report.add_header("7. 🎯 Comparação com Vulnerabilidades Conhecidas do DVWA", 2)
    
    coverage = compare_with_known_vulnerabilities(trivy_container, semgrep, zap, hydra, zap_active)

    total_known = len(coverage['detected']) + len(coverage['not_detected'])
    coverage_pct = (len(coverage['detected']) / total_known * 100) if total_known > 0 else 0

    report.add(f"**Vulnerabilidades conhecidas do DVWA:** {total_known}")
    report.add()
    report.add(f"**Detectadas pelo pipeline:** {len(coverage['detected'])} ({coverage_pct:.1f}%)")
    report.add()
    report.add(f"**Não detectadas:** {len(coverage['not_detected'])} ({100-coverage_pct:.1f}%)")
    report.add()

    report.add_header("✅ Vulnerabilidades Detectadas", 3)
    if coverage['detected']:
        report.add_table(
            ["Vulnerabilidade", "Categoria", "CWE", "Ferramenta", "Descrição"],
            [[v['name'], v['category'], v['cwe'], v.get('ferramenta', '-'), v['description']] for v in coverage['detected']]
        )
    else:
        report.add("Nenhuma vulnerabilidade conhecida foi detectada.")
    report.add()

    report.add_header("❌ Vulnerabilidades Não Detectadas", 3)
    if coverage['not_detected']:
        report.add_table(
            ["Vulnerabilidade", "Categoria", "CWE", "OWASP", "Motivo", "Sugestão"],
            [
                [
                    v['name'],
                    v['category'],
                    v['cwe'],
                    v.get('owasp', 'N/A')[:30] if v.get('owasp') else 'N/A',
                    v.get('motivo', '-'),
                    v.get('sugestao', '-')
                ]
                for v in coverage['not_detected']
            ]
        )
    report.add()

    # Seção de análise de cobertura agora é apenas um sumário dinâmico
    total = len(coverage['detected']) + len(coverage['not_detected'])
    pct = (len(coverage['detected']) / total * 100) if total > 0 else 0
    report.add_header("Resumo da Cobertura", 3)
    
    # Avaliação qualitativa baseada na porcentagem
    if pct >= 90:
        qualidade = "🏆 **EXCELENTE** - O pipeline demonstra alta maturidade em detecção de vulnerabilidades"
    elif pct >= 80:
        qualidade = "🌟 **MUITO BOM** - O pipeline tem uma cobertura sólida com pequenos pontos de melhoria"
    elif pct >= 70:
        qualidade = "✅ **BOM** - O pipeline atende aos requisitos básicos de segurança, mas há espaço para melhorias"
    elif pct >= 50:
        qualidade = "⚠️ **REGULAR** - O pipeline precisa de melhorias significativas para uma cobertura adequada"
    else:
        qualidade = "❌ **INSUFICIENTE** - O pipeline necessita de revisão urgente na estratégia de testes de segurança"
    
    report.add(f"Cobertura do pipeline: **{len(coverage['detected'])}/{total}** vulnerabilidades conhecidas detectadas (**{pct:.1f}%**)")
    report.add()
    report.add(f"**Avaliação:** {qualidade}")
    report.add()
    
    if coverage['not_detected']:
        report.add("Principais motivos para não detecção:")
        motivos = set(v['motivo'] for v in coverage['not_detected'])
        for m in motivos:
            report.add(f"- {m}")
        report.add()
        report.add("Sugestões para aumentar a cobertura:")
        sugestoes = set(v['sugestao'] for v in coverage['not_detected'] if v['sugestao'] and v['sugestao'] != '-')
        for s in sugestoes:
            report.add(f"- {s}")
        report.add()
    
    # ========================================================================
    # SEÇÃO 7.1: VALIDAÇÃO DA COBERTURA DO ZAP ACTIVE SCAN
    # ========================================================================
    report.add_header("7.1 🔬 Validação da Cobertura do ZAP Active Scan", 2)
    
    zap_coverage = validate_zap_coverage("zap-auth-active-report.json")
    
    report.add(f"**Score de cobertura de injeção:** {zap_coverage['coverage_score']:.1f}%")
    report.add()
    
    # Mostrar alerta de timeout se aplicável
    if zap_coverage.get("timeout", False):
        report.add("### ⏱️ TIMEOUT - Scan Incompleto")
        report.add()
        report.add("**O Active Scan não completou dentro do limite de 10 minutos.** Os resultados abaixo são parciais e podem não refletir todas as vulnerabilidades existentes.")
        report.add()
        report.add("*Para um scan completo, considere:*")
        report.add("- *Executar o ZAP localmente com mais tempo*")
        report.add("- *Aumentar o timeout na pipeline (pode impactar custos)*")
        report.add("- *Limitar o escopo do scan a URLs específicas*")
        report.add()
    
    # Explicação contextual do score
    report.add("*Nota: Este score mede especificamente a detecção de vulnerabilidades de **injeção** (SQLi, XSS, Command Injection) que são o foco do Active Scan. O ZAP Active Scan **detectou outros tipos de vulnerabilidades** (configuração de headers, cookies, CORS, etc.) que são válidas mas não entram neste cálculo específico.*")
    report.add()
    
    # Resumo do que foi efetivamente detectado pelo Active Scan
    if zap_active and 'alerts' in zap_active and zap_active['alerts']:
        detected_cwe_types = set()
        for alert in zap_active['alerts']:
            cwe = alert.get('cwe', alert.get('cweid', ''))
            if cwe and cwe not in ('', '0', '-1'):
                detected_cwe_types.add(str(cwe))
        if detected_cwe_types:
            report.add(f"**CWEs efetivamente detectados pelo Active Scan:** {', '.join([f'CWE-{c}' for c in sorted(detected_cwe_types, key=lambda x: int(x) if x.isdigit() else 0)])}")
            report.add()
            report.add("Estes CWEs representam vulnerabilidades reais encontradas (ex: cabeçalhos de segurança ausentes, configurações inseguras de cookies), mesmo que não sejam vulnerabilidades de injeção.")
            report.add()
    
    if zap_coverage["cwes_detected"]:
        report.add_header("CWEs de Injeção Detectados", 3)
        report.add_table(
            ["CWE", "Vulnerabilidade", "Crítico"],
            [[c["cwe"], c["name"], "✅ Sim" if c["required"] else "Não"] for c in zap_coverage["cwes_detected"]]
        )
    
    if zap_coverage["cwes_missing"]:
        report.add_header("CWEs de Injeção Esperados mas Não Detectados", 3)
        report.add_table(
            ["CWE", "Vulnerabilidade", "Crítico", "URLs Esperadas"],
            [[c["cwe"], c["name"], "⚠️ Sim" if c["required"] else "Não", ", ".join(c["expected_urls"])] for c in zap_coverage["cwes_missing"]]
        )
        report.add()
        
        # Diagnóstico detalhado: verificar se plugins de ataque foram executados
        injection_plugins = zap_coverage.get("injection_plugins_executed", [])
        all_plugins = zap_coverage.get("all_plugins_found", [])
        
        if not injection_plugins:
            report.add("### 🔍 Diagnóstico: Plugins de Ataque")
            report.add()
            report.add("**⚠️ NENHUM plugin de ataque de injeção foi executado durante o Active Scan.**")
            report.add()
            report.add("Plugins encontrados no relatório (todos são scanners passivos):")
            report.add(f"- `{', '.join(all_plugins[:10])}`" if all_plugins else "- Nenhum")
            report.add()
            report.add("Plugins de injeção esperados (não encontrados):")
            report.add("- `40018` - SQL Injection")
            report.add("- `40012` - XSS (Reflected)")
            report.add("- `90020` - Remote OS Command Injection")
            report.add()
            report.add("**Causa Provável:** O ZAP não conseguiu manter sessão autenticada durante o Active Scan.")
            report.add("Quando o ZAP tenta acessar `/vulnerabilities/sqli/` sem cookie de sessão válido, é redirecionado para `/login.php`.")
            report.add()
        
        report.add("*A não detecção de vulnerabilidades de injeção pelo Active Scan pode ocorrer por:*")
        report.add("- *Sessão HTTP não configurada corretamente no ZAP (cookies não persistem entre requisições)*")
        report.add("- *DVWA configurado em nível de segurança 'Medium' ou 'High' que bloqueia payloads comuns*")
        report.add("- *Timeouts do scan ou limitações de profundidade configurados*")
        report.add("- *Necessidade de contexto de autenticação mais específico*")
    
    if zap_coverage["urls_tested"]:
        report.add_header("URLs Vulneráveis Testadas", 3)
        for url in zap_coverage["urls_tested"][:10]:  # Limitar a 10
            report.add(f"- ✅ `{url}`")
        report.add()
    
    if zap_coverage["urls_missing"]:
        report.add_header("URLs Vulneráveis Não Testadas", 3)
        for url in zap_coverage["urls_missing"]:
            report.add(f"- ❌ `{url}`")
        report.add()
    
    if zap_coverage["issues"]:
        report.add_header("Problemas Identificados", 3)
        for issue in zap_coverage["issues"]:
            report.add(f"- ⚠️ {issue}")
        report.add()
    
    if zap_coverage["recommendations"]:
        report.add_header("Recomendações para Melhorar Cobertura DAST", 3)
        for rec in zap_coverage["recommendations"]:
            report.add(f"- 💡 {rec}")
        report.add()
    
    # ========================================================================
    # SEÇÃO 7.2: LIMITAÇÕES IDENTIFICADAS NA ANÁLISE
    # ========================================================================
    report.add_header("7.2 ⚠️ Limitações Identificadas na Análise", 2)
    
    limitations = detect_analysis_limitations()
    has_limitations = any(lims for lims in limitations.values())
    
    if has_limitations:
        report.add("As seguintes limitações foram identificadas dinamicamente durante a análise:")
        report.add()
        
        category_names = {
            "sast": "SAST (Análise Estática)",
            "sca": "SCA (Análise de Composição)",
            "dast": "DAST (Análise Dinâmica)",
            "iac": "IaC (Infraestrutura como Código)",
            "container": "Container Scan",
            "bruteforce": "Teste de Força Bruta"
        }
        
        for category, lims in limitations.items():
            if lims:
                report.add_header(category_names.get(category, category), 3)
                for lim in lims:
                    report.add(f"**Problema:** {lim['issue']}")
                    report.add()
                    report.add(f"- **Impacto:** {lim['impact']}")
                    report.add(f"- **Recomendação:** {lim['recommendation']}")
                    report.add()
    else:
        report.add("✅ Nenhuma limitação significativa identificada na análise.")
        report.add()
    
    # ========================================================================
    # SEÇÃO 8: CONCLUSÕES E RECOMENDAÇÕES
    # ========================================================================
    report.add_header("8. 📝 Conclusões e Recomendações", 2)
    
    report.add_header("Principais Descobertas", 3)
    
    # Descobertas dinâmicas baseadas nos dados
    discoveries = []
    
    # 1. Sistema Operacional
    if trivy_container and trivy_container.get('eosl'):
        os_name = trivy_container.get('os', 'N/A')
        critical_count = trivy_container['by_severity'].get('CRITICAL', 0)
        high_count = trivy_container['by_severity'].get('HIGH', 0)
        discoveries.append(f"""1. **RISCO CRÍTICO - SISTEMA OPERACIONAL**
   - A imagem base utiliza {os_name}, que está em End of Support Life (EOSL)
   - Foram encontradas {critical_count} vulnerabilidades CRÍTICAS e {high_count} de ALTA severidade
   - Recomendação: Migrar para imagem base com suporte ativo""")
    
    # 2. Kubernetes/IaC
    if checkov and checkov.get('failed', 0) > 0:
        iac_issues = checkov['failed']
        discoveries.append(f"""2. **CONFIGURAÇÃO KUBERNETES/IAC**
   - Checkov identificou {iac_issues} problemas de configuração de segurança
   - Incluem: SecurityContext, RBAC, Network Policies, entre outros
   - Recomendação: Revisar e aplicar as correções sugeridas pelo Checkov""")
    
    # 3. SAST
    if semgrep:
        sast_findings = len(semgrep.get('findings', []))
        if sast_findings > 0:
            discoveries.append(f"""3. **ANÁLISE ESTÁTICA (SAST)**
   - Semgrep identificou {sast_findings} potenciais problemas no código
   - CWEs encontrados: {', '.join(list(semgrep.get('by_cwe', {}).keys())[:5])}
   - Recomendação: Revisar e corrigir os findings de alta prioridade""")
        else:
            discoveries.append(f"""3. **ANÁLISE ESTÁTICA (SAST)**
   - Semgrep não encontrou vulnerabilidades significativas no código analisado
   - Indica boas práticas de desenvolvimento seguro""")
    
    # 4. DAST
    zap_baseline_alerts = len(zap.get('alerts', [])) if zap and 'alerts' in zap else 0
    zap_active_alerts = len(zap_active.get('alerts', [])) if zap_active and 'alerts' in zap_active else 0
    total_dast_alerts = zap_baseline_alerts + zap_active_alerts
    
    if total_dast_alerts > 0:
        dast_details = []
        if zap_baseline_alerts > 0:
            dast_details.append(f"Baseline Scan: {zap_baseline_alerts} alertas")
        if zap_active_alerts > 0:
            dast_details.append(f"Active Scan: {zap_active_alerts} alertas")
        discoveries.append(f"""4. **ANÁLISE DINÂMICA (DAST)**
   - OWASP ZAP identificou {total_dast_alerts} alertas totais ({', '.join(dast_details)})
   - Vulnerabilidades web detectadas incluem headers ausentes, cookies inseguros, etc.
   - Active Scan permite detecção de SQLi, XSS e outras vulnerabilidades de injeção""")
    
    # 5. Brute Force
    if hydra:
        if hydra.get('vulnerable'):
            discoveries.append(f"""5. **TESTE DE FORÇA BRUTA**
   - ⚠️ Hydra detectou credenciais fracas na aplicação
   - A aplicação é vulnerável a ataques de força bruta
   - Recomendação: Implementar rate limiting e políticas de senha fortes""")
        else:
            discoveries.append(f"""5. **TESTE DE FORÇA BRUTA**
   - Hydra não conseguiu encontrar credenciais por força bruta
   - Pode indicar proteção adequada ou necessidade de ajuste no teste""")
    
    for discovery in discoveries:
        report.add(discovery)
        report.add()
    
    report.add_header("Eficácia do Pipeline", 3)
    
    # Pontos fortes dinâmicos
    strengths = []
    
    total_findings = 0
    if trivy_container:
        total_findings += len(trivy_container.get('vulnerabilities', []))
    if semgrep:
        total_findings += len(semgrep.get('findings', []))
    if zap and 'alerts' in zap:
        total_findings += len(zap['alerts'])
    if zap_active and 'alerts' in zap_active:
        total_findings += len(zap_active['alerts'])
    if checkov:
        total_findings += len(checkov.get('findings', []))
    
    strengths.append(f"✅ Detecção automatizada de {total_findings} vulnerabilidades/issues")
    strengths.append("✅ Execução totalmente integrada ao CI/CD (Cloud Build)")
    
    # Contar camadas de análise ativas
    layers = []
    if trivy_container:
        layers.append("Container")
    if checkov:
        layers.append("IaC")
    if trivy_sca:
        layers.append("SCA")
    if semgrep:
        layers.append("SAST")
    if zap or zap_active:
        layers.append("DAST")
    if hydra:
        layers.append("Brute Force")
    
    strengths.append(f"✅ {len(layers)} camadas de análise ({', '.join(layers)})")
    
    if zap_active and 'alerts' in zap_active:
        strengths.append(f"✅ DAST com Active Scan autenticado ({zap_active_alerts} alertas)")
    elif zap and 'alerts' in zap:
        strengths.append(f"✅ DAST funcional com {zap_baseline_alerts} tipos de alertas")
    
    strengths.append("✅ Relatórios estruturados em JSON para análise automatizada")
    strengths.append("✅ Pipeline sem hardcode (usa substituições do Cloud Build)")
    
    report.add("**PONTOS FORTES:**")
    for s in strengths:
        report.add(f"- {s}")
    report.add()
    
    # Pontos de melhoria dinâmicos
    improvements = []
    
    # Verificar se há SAST para código da aplicação (PHP)
    if not semgrep or len(semgrep.get('findings', [])) == 0:
        improvements.append("⚠️ Considerar adicionar SAST específico para PHP (PHPStan, Psalm)")
    
    # Verificar cobertura
    if coverage_pct < 70:
        improvements.append(f"⚠️ Cobertura de {coverage_pct:.1f}% das vulnerabilidades conhecidas - avaliar testes adicionais")
    
    # ZAP Active Scan
    if not zap_active or 'alerts' not in zap_active or len(zap_active.get('alerts', [])) == 0:
        improvements.append("⚠️ ZAP Active Scan não gerou resultados - verificar configuração")
    
    # Hydra
    if not hydra or (not hydra.get('vulnerable') and 'erro' in hydra.get('result', '').lower()):
        improvements.append("⚠️ Verificar configuração do Hydra para testes de força bruta")
    
    if improvements:
        report.add("**PONTOS DE MELHORIA:**")
        for i in improvements:
            report.add(f"- {i}")
        report.add()
    
    report.add_header("Cobertura de Vulnerabilidades DVWA", 3)
    report.add(f"**Total de vulnerabilidades conhecidas:** {total_known}")
    report.add()
    report.add(f"**Detectadas pelo pipeline:** {len(coverage['detected'])} ({coverage_pct:.1f}%)")
    report.add()
    report.add(f"**Não detectadas:** {len(coverage['not_detected'])} ({100-coverage_pct:.1f}%)")
    report.add()
    
    # Análise das não detectadas
    if coverage['not_detected']:
        report.add("**Motivos para não detecção:**")
        motivos_unicos = set()
        for v in coverage['not_detected']:
            motivos_unicos.add(v.get('motivo', 'N/A'))
        for m in motivos_unicos:
            report.add(f"- {m}")
        report.add()
    
    report.add_header("Recomendações Baseadas nos Resultados", 3)
    
    recommendations = []
    
    # Recomendações baseadas nos dados
    if trivy_container and trivy_container.get('eosl'):
        recommendations.append("🔴 **URGENTE:** Migrar para imagem base com suporte ativo (ex: Debian 11/12, Alpine)")
    
    if trivy_container and trivy_container['by_severity'].get('CRITICAL', 0) > 50:
        recommendations.append("🔴 **URGENTE:** Aplicar patches para CVEs críticas ou reconstruir imagem")
    
    if checkov and checkov.get('failed', 0) > 10:
        recommendations.append("🟠 **ALTA:** Corrigir configurações de segurança do Kubernetes/IaC")
    
    if coverage_pct < 80:
        recommendations.append("🟡 **MÉDIA:** Aumentar cobertura de testes de segurança")
    
    recommendations.append("🟢 **CONTÍNUA:** Manter pipeline atualizado com novas regras de segurança")
    recommendations.append("🟢 **CONTÍNUA:** Integrar resultados com sistema de gestão de vulnerabilidades")
    
    for rec in recommendations:
        report.add(f"- {rec}")
    report.add()
    
    report.add("---")
    report.add()
    report.add(f"*Relatório gerado automaticamente em {datetime.now().strftime('%d/%m/%Y às %H:%M:%S')}*")
    
    # Salvar relatório
    report.save("relatorio-vulnerabilidades.md")
    
    return report


if __name__ == '__main__':
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    print("🔄 Gerando relatório de análise...")
    print()
    generate_report()
    print()
    print("✅ Arquivo gerado: relatorio-vulnerabilidades.md")
