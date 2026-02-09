# 📊 Relatórios de Segurança

Este diretório contém os relatórios gerados pelas ferramentas de segurança durante a execução da pipeline DevSecOps.

## 📁 Estrutura

| Arquivo | Ferramenta | Descrição |
|---------|------------|-----------|
| `analise.py` | Python | Script que processa todos os relatórios e gera análise consolidada |
| `relatorio-vulnerabilidades.md` | - | Relatório final em Markdown com análise completa |
| `*_trivy-report.json` | Trivy | Container Scan - vulnerabilidades na imagem Docker |
| `*_trivy-sca-report.json` | Trivy | SCA - análise de dependências |
| `*_semgrep-report.json` | Semgrep | SAST - análise estática de código |
| `*_checkov-report.json` | Checkov | IaC Scan - análise de Terraform |
| `*_checkov-k8s.json` | Checkov | IaC Scan - análise de manifests K8s |
| `*_zap-report.json` | OWASP ZAP | DAST - Baseline Scan (passivo) |
| `*_zap-auth-active-report.json` | OWASP ZAP | DAST - Active Scan autenticado |
| `*_hydra-bruteforce.json` | Script Python | Teste de força bruta |
| `ZAP *.html` | OWASP ZAP | Relatórios HTML para visualização |

## 🔄 Como Gerar o Relatório

```bash
# Na pasta Reports/
python3 analise.py

# O relatório será gerado em:
# relatorio-vulnerabilidades.md
```

## 📈 Métricas Principais

- **Cobertura Geral:** 76.5% (13/17 vulnerabilidades DVWA)
- **Cobertura Ajustada:** 100% (13/13 - escopo automatizável)
- **Total de Findings:** ~1750 (todas as ferramentas)

## ⚠️ Observações

- Os arquivos JSON com prefixo `reports-COMMIT_*` são os relatórios oficiais versionados
- O script `analise.py` seleciona automaticamente o relatório mais recente de cada tipo
- Relatórios HTML são para visualização, os dados são extraídos dos JSON
