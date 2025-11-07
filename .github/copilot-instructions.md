# AI Agent Instructions for SOC-Project

This document guides AI coding agents in understanding and working with this Security Operations Center (SOC) integration project.

## Project Architecture

This is a modular SOC environment integrating:
- Wazuh (SIEM)
- Elasticsearch/Kibana (data store and visualization)
- Shuffle (SOAR orchestration)
- Custom XAI (Explainable AI) analysis
- Azure Sentinel (cloud SIEM integration)

Key data flows:
1. Wazuh → Logstash → Elasticsearch/Sentinel (alert ingestion)
2. Alerts → XAI Analysis → Enrichment → Sentinel (intelligent processing)
3. Kibana/Jupyter → Elasticsearch (visualization and analysis)

## Critical Files & Components

- `setup-local-soc-siem-soar-xai-sentinel.ps1`: Master installation script
- `config.json`: Central configuration for all components
- `xai/xai_agent.py`: Core XAI analysis engine
- `scripts/send_alerts_to_sentinel.py`: Sentinel integration
- `logstash/pipelines/wazuh-to-sentinel.conf`: Alert flow configuration
- `shuffle/playbook-*.yaml`: SOAR automation workflows

## Developer Workflows

### Environment Setup
```powershell
# Install with default settings
.\setup-local-soc-siem-soar-xai-sentinel.ps1

# Skip specific components
.\setup-local-soc-siem-soar-xai-sentinel.ps1 -SkipWazuh -SkipKibana
```

### Health Checks
Use `scripts/utils.ps1` functions:
```powershell
Get-SOCStatus  # Check all component health
Test-WazuhConfiguration  # Validate Wazuh setup
Get-ElasticsearchHealth  # Check ES cluster
```

### Alert Analysis
1. Use `scripts/visualize_alerts.ipynb` for interactive analysis
2. Monitor Kibana dashboards (port 5601)
3. Check Sentinel workbooks for cloud analytics

## Development Patterns

### XAI Integration
- Extend `XAIAgent` class in `xai_agent.py`
- New models must implement:
  - `analyze_alert()`
  - `generate_explanation()`
  - Feature preprocessing

### Alert Pipeline Modification
1. Edit Logstash pipeline config
2. Add enrichment in `wazuh-to-sentinel.conf`
3. Update Sentinel schema if needed

### SOAR Automation
- New playbooks go in `shuffle/*.yaml`
- Follow existing playbook structure:
  - Trigger conditions
  - Actions sequence
  - XAI integration points

## Key Integration Points

- Wazuh Manager: Port 1514 (agent communication)
- Elasticsearch: Port 9200 (data store)
- Logstash: Port 5044 (log ingestion)
- Shuffle API: Port 3001 (automation)
- Kibana: Port 5601 (visualization)

## Common Development Tasks

### Adding New Alert Types
1. Configure Wazuh rules
2. Update Logstash pipeline filters
3. Add XAI feature extraction
4. Create Shuffle automation playbook
5. Update visualization notebooks

### Modifying XAI Analysis
1. Extend model in `xai_agent.py`
2. Update feature preprocessing
3. Add new explanation types
4. Test with example alerts

### Sentinel Integration
- Use `SentinelConnector` class from `send_alerts_to_sentinel.py`
- Follow authentication and request signing patterns
- Test with sample alerts before production