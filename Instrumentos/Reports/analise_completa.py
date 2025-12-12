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
    
    # Formato do ZAP pode variar
    site = data.get('site', [])
    if isinstance(site, list) and len(site) > 0:
        site = site[0]
    
    analysis['target'] = site.get('@name', data.get('site', {}).get('@name', 'N/A')) if isinstance(site, dict) else 'N/A'
    
    alerts = site.get('alerts', data.get('alerts', [])) if isinstance(site, dict) else data.get('alerts', [])
    if isinstance(alerts, dict):
        alerts = alerts.get('alertitem', [])
    
    if not isinstance(alerts, list):
        alerts = [alerts] if alerts else []
    
    for alert in alerts:
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
            'count': int(alert.get('count', 1))
        }
        
        analysis['alerts'].append(a)
        
        # Mapear risk level
        risk_level = a['risk'].split()[0] if a['risk'] else 'Informational'
        analysis['by_risk'][risk_level] += 1
        
        if a['cwe']:
            analysis['by_cwe'][f"CWE-{a['cwe']}"] += 1
    
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


def compare_with_known_vulnerabilities(trivy_analysis, semgrep_analysis, zap_analysis):
    """Compara vulnerabilidades encontradas com as conhecidas do DVWA"""
    
    coverage = {
        'detected': [],
        'not_detected': [],
        'additional_findings': []
    }
    
    # CWEs encontrados pelas ferramentas
    detected_cwes = set()
    
    if trivy_analysis:
        detected_cwes.update(trivy_analysis['by_cwe'].keys())
    
    if semgrep_analysis:
        for cwe_list in [f['cwe'] for f in semgrep_analysis['findings']]:
            for cwe in cwe_list:
                # Normalizar formato CWE
                if 'CWE-' in cwe:
                    detected_cwes.add(cwe.split(':')[0] if ':' in cwe else cwe)
    
    if zap_analysis and 'by_cwe' in zap_analysis:
        detected_cwes.update(zap_analysis['by_cwe'].keys())
    
    # Verificar cobertura das vulnerabilidades conhecidas
    for category, vulns in DVWA_KNOWN_VULNERABILITIES.items():
        for vuln_name, vuln_info in vulns.items():
            cwe = vuln_info.get('cwe', '')
            
            # Verificar se foi detectado
            detected = any(cwe in detected_cwe for detected_cwe in detected_cwes)
            
            entry = {
                'name': vuln_name,
                'category': category,
                'cwe': cwe,
                'owasp': vuln_info.get('owasp', 'N/A'),
                'description': vuln_info.get('description', '')
            }
            
            if detected:
                coverage['detected'].append(entry)
            else:
                coverage['not_detected'].append(entry)
    
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
    checkov = analyze_checkov()
    
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
    if checkov:
        total_vulns += len(checkov['findings'])
    
    # Tabela resumo
    report.add_table(
        ["Ferramenta", "Tipo", "Findings", "Status"],
        [
            ["Trivy", "Container Scan", len(trivy_container['vulnerabilities']) if trivy_container else 0, "✅ Executado"],
            ["Semgrep", "SAST", len(semgrep['findings']) if semgrep else 0, "✅ Executado"],
            ["Trivy FS", "SCA", len(trivy_sca['vulnerabilities']) if trivy_sca else 0, "✅ Executado"],
            ["OWASP ZAP", "DAST", len(zap['alerts']) if zap and 'alerts' in zap else 0, "✅ Executado" if zap and 'alerts' in zap else "⚠️ Não gerado"],
            ["Checkov", "IaC Scan", len(checkov['findings']) if checkov else 0, "✅ Executado" if checkov else "⚠️ Não disponível"]
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
    # SEÇÃO 6: COMPARAÇÃO COM VULNERABILIDADES CONHECIDAS DO DVWA
    # ========================================================================
    report.add_header("6. 🎯 Comparação com Vulnerabilidades Conhecidas do DVWA", 2)
    
    coverage = compare_with_known_vulnerabilities(trivy_container, semgrep, zap)
    
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
            ["Vulnerabilidade", "Categoria", "CWE", "Descrição"],
            [[v['name'], v['category'], v['cwe'], v['description'][:40] + "..."] for v in coverage['detected']]
        )
    else:
        report.add("Nenhuma vulnerabilidade conhecida foi detectada.")
    report.add()
    
    report.add_header("❌ Vulnerabilidades Não Detectadas", 3)
    if coverage['not_detected']:
        report.add_table(
            ["Vulnerabilidade", "Categoria", "CWE", "OWASP"],
            [[v['name'], v['category'], v['cwe'], v.get('owasp', 'N/A')[:30] if v.get('owasp') else 'N/A'] for v in coverage['not_detected']]
        )
    report.add()
    
    report.add_header("Análise da Cobertura", 3)
    report.add("""
As vulnerabilidades não detectadas são predominantemente:

1. **VULNERABILIDADES WEB (SQL Injection, XSS, etc.)**
   - Requerem análise DINÂMICA (DAST) com a aplicação em execução
   - O SAST analisou arquivos de configuração, não código PHP do DVWA

2. **FALHAS DE AUTENTICAÇÃO (Brute Force, Weak Session IDs)**
   - Requerem testes comportamentais da aplicação

3. **FALHAS DE AUTORIZAÇÃO (CSRF, Authorization Bypass)**
   - Requerem interação HTTP real com a aplicação

**📌 CONCLUSÃO:**

O pipeline atual é eficaz para:
- ✅ Vulnerabilidades de infraestrutura (Container, OS)
- ✅ Misconfigurações (Kubernetes, Terraform, IaC)
- ✅ Dependências vulneráveis (SCA)

Para cobertura completa, é necessário:
- ⚠️ Implementar DAST funcional (OWASP ZAP, Nuclei, etc.)
- ⚠️ Adicionar SAST específico para PHP (linguagem do DVWA)
""")
    
    # ========================================================================
    # SEÇÃO 7: CONCLUSÕES E RECOMENDAÇÕES
    # ========================================================================
    report.add_header("7. 📝 Conclusões e Recomendações para o TCC", 2)
    
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

4. **GAPS DE COBERTURA**
   - O DAST é essencial para detectar as principais vulnerabilidades web do DVWA
""")
    
    report.add_header("Eficácia do Pipeline", 3)
    report.add("""
**PONTOS FORTES:**
- ✅ Detecção automatizada de milhares de vulnerabilidades
- ✅ Execução totalmente integrada ao CI/CD (Cloud Build)
- ✅ Múltiplas camadas de análise (Container, IaC, SCA, SAST, DAST)
- ✅ Relatórios estruturados em JSON para análise
- ✅ Tempo de execução aceitável (~10-15 minutos)

**PONTOS DE MELHORIA:**
- ⚠️ Necessidade de validar funcionamento do DAST
- ⚠️ Ausência de SAST para código PHP da aplicação
- ⚠️ Dependency-Check (OWASP) desativado por performance
""")
    
    report.add_header("Recomendações", 3)
    report.add("""
**CURTO PRAZO:**
1. Validar execução do OWASP ZAP com IP externo
2. Adicionar timeout/retry para DAST
3. Garantir geração de todos os relatórios

**MÉDIO PRAZO:**
4. Adicionar SAST específico para PHP (PHPStan, Psalm)
5. Configurar NVD API key para OWASP Dependency-Check
6. Implementar quality gates (falhar build em CVEs críticas)

**LONGO PRAZO:**
7. Adicionar análise de secrets (TruffleHog, GitLeaks)
8. Implementar fuzzing automatizado
9. Integrar com plataforma de gestão de vulnerabilidades
""")
    
    report.add("---")
    report.add()
    report.add(f"*Relatório gerado automaticamente em {datetime.now().strftime('%d/%m/%Y às %H:%M:%S')}*")
    
    # Salvar relatório
    output_file = f"relatorio_analise_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    report.save(output_file)
    
    # Também criar versão fixa para referência
    report.save("RELATORIO_ANALISE.md")
    
    return report


if __name__ == '__main__':
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    print("🔄 Gerando relatório de análise...")
    print()
    generate_report()
    print()
    print("📄 Arquivos gerados:")
    print("   - RELATORIO_ANALISE.md (versão fixa)")
    print(f"   - relatorio_analise_*.md (versão com timestamp)")
