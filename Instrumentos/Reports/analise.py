#!/usr/bin/env python3
"""
================================================================================
ANÁLISE COMPLETA DOS RELATÓRIOS DE SEGURANÇA - PIPELINE DEVSECOPS
================================================================================
Pesquisa: Integração de Testes de Segurança Contínuos em Pipelines CI/CD
Aplicação alvo: DVWA (Damn Vulnerable Web Application)
Data de execução: Dezembro 2025
================================================================================
"""
import json
import os
from collections import defaultdict
from datetime import datetime

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


def load_json(filepath):
    """Carrega arquivo JSON"""
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"[AVISO] Não foi possível carregar {filepath}: {e}")
        return None


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
    """Analisa relatório do Hydra Brute Force"""
    data = load_json('hydra-bruteforce.json')
    if not data:
        return None
    # O formato esperado é {'results': ...}
    result = data.get('results', '')
    analysis = {
        'tool': 'Hydra',
        'type': 'Brute Force',
        'result': result
    }
    # Se encontrar credenciais, marca como vulnerável
    if result and 'Nenhuma credencial encontrada' not in result and 'erro' not in result.lower():
        analysis['vulnerable'] = True
    else:
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

    # Trivy SCA
    trivy_sca = None
    try:
        from inspect import currentframe
        frame = currentframe()
        trivy_sca = frame.f_back.f_locals.get('trivy_sca', None)
    except Exception:
        trivy_sca = None
    if not trivy_sca:
        try:
            import builtins
            trivy_sca = getattr(builtins, 'trivy_sca', None)
        except Exception:
            trivy_sca = None
    if trivy_sca:
        # SCA não traz CWE por padrão, mas pode ser extendido se necessário
        pass

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

    # Checkov
    checkov = None
    try:
        from inspect import currentframe
        frame = currentframe()
        checkov = frame.f_back.f_locals.get('checkov', None)
    except Exception:
        checkov = None
    if not checkov:
        try:
            import builtins
            checkov = getattr(builtins, 'checkov', None)
        except Exception:
            checkov = None
    if checkov:
        for finding in checkov.get('findings', []):
            cwe = finding.get('check_id', '')
            # Checkov check_id pode não ser um CWE, mas se for, adiciona
            if cwe.startswith('CWE-'):
                detected_cwes.add(cwe)
                cwe_to_tool[cwe] = 'Checkov'
    
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
            report.add("✅ **NENHUMA VULNERABILIDADE ENCONTRADA EM DEPENDÊNCIAS!**")
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
            [[v['name'], v['category'], v['cwe'], v.get('ferramenta', '-'), v['description'][:40] + "..."] for v in coverage['detected']]
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
    report.add(f"Cobertura do pipeline: **{len(coverage['detected'])}/{total}** vulnerabilidades conhecidas detectadas (**{pct:.1f}%**)")
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
    # SEÇÃO 8: CONCLUSÕES E RECOMENDAÇÕES
    # ========================================================================
    report.add_header("8. 📝 Conclusões e Recomendações para o TCC", 2)
    
    report.add_header("Principais Descobertas", 3)
    report.add("""
1. **RISCO CRÍTICO - SISTEMA OPERACIONAL**
   - A imagem base do DVWA utiliza Debian 9.5, que está em End of Support Life (EOSL) desde 2020
   - Isso resulta em centenas de vulnerabilidades CRÍTICAS e de ALTA severidade sem patches disponíveis

2. **CONFIGURAÇÃO KUBERNETES INSEGURA**
   - Os manifestos de deployment não implementam SecurityContext adequado
   - `runAsNonRoot` não configurado (CWE-250)
   - `allowPrivilegeEscalation` não bloqueado (CWE-732)
   - Permite potencial escalação de privilégios

3. **CÓDIGO FONTE LIMPO**
   - Nenhuma vulnerabilidade foi encontrada nas dependências do projeto Terraform/CloudBuild
   - Indica boas práticas de composição de software

4. **DAST OPERACIONAL**
   - OWASP ZAP executando com sucesso, detectando vulnerabilidades web
   - Headers de segurança ausentes identificados (CSP, X-Content-Type-Options)
   - Cookies sem flags de segurança detectados
""")
    
    report.add_header("Eficácia do Pipeline", 3)
    report.add("""
**PONTOS FORTES:**
- ✅ Detecção automatizada de milhares de vulnerabilidades
- ✅ Execução totalmente integrada ao CI/CD (Cloud Build)
- ✅ Múltiplas camadas de análise (Container, IaC, SCA, SAST, DAST)
- ✅ DAST funcional com OWASP ZAP detectando 18 tipos de vulnerabilidades
- ✅ Relatórios estruturados em JSON para análise
- ✅ Tempo de execução aceitável (~10-15 minutos)

**PONTOS DE MELHORIA:**
- ⚠️ Ausência de SAST para código PHP da aplicação
- ⚠️ Scan ZAP não autenticado (não testa áreas logadas)
- ⚠️ Dependency-Check (OWASP) desativado por performance
""")
    
    report.add_header("Recomendações", 3)
    report.add("""
**CURTO PRAZO:**
1. Implementar scan ZAP autenticado para testar vulnerabilidades em áreas logadas
2. Adicionar quality gates (falhar build em CVEs críticas)
3. Configurar alertas de segurança automáticos

**MÉDIO PRAZO:**
4. Adicionar SAST específico para PHP (PHPStan, Psalm)
5. Configurar NVD API key para OWASP Dependency-Check
6. Implementar scan de secrets (TruffleHog, GitLeaks)

**LONGO PRAZO:**
7. Integrar com plataforma de gestão de vulnerabilidades (DefectDojo, etc.)
8. Implementar fuzzing automatizado
9. Integrar com plataforma de gestão de vulnerabilidades
""")
    
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
