# Helper functions for SOC environment management

function Test-Port {
    param(
        [string]$ComputerName = "localhost",
        [int]$Port
    )
    
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $tcp.Connect($ComputerName, $Port)
        $tcp.Close()
        return $true
    } catch {
        return $false
    }
}

function Get-ServiceStatus {
    param(
        [string]$ServiceName
    )
    
    try {
        $service = Get-Service -Name $ServiceName -ErrorAction Stop
        return @{
            Name = $service.Name
            Status = $service.Status
            StartType = $service.StartType
        }
    } catch {
        return @{
            Name = $ServiceName
            Status = "Not Found"
            StartType = "Unknown"
        }
    }
}

function Test-DockerContainer {
    param(
        [string]$ContainerName
    )
    
    try {
        $container = docker ps --filter "name=$ContainerName" --format "{{.Status}}"
        if ($container) {
            return @{
                Name = $ContainerName
                Status = $container
                Running = $true
            }
        } else {
            return @{
                Name = $ContainerName
                Status = "Not Running"
                Running = $false
            }
        }
    } catch {
        return @{
            Name = $ContainerName
            Status = "Error: $_"
            Running = $false
        }
    }
}

function Get-ElasticsearchHealth {
    param(
        [string]$ElasticHost = "localhost",
        [int]$ElasticPort = 9200
    )
    
    try {
        $response = Invoke-RestMethod -Uri "http://${ElasticHost}:${ElasticPort}/_cluster/health" -Method Get
        return $response
    } catch {
        return @{
            status = "error"
            error = $_.Exception.Message
        }
    }
}

function Test-WazuhConfiguration {
    param(
        [string]$WazuhPath = "C:\Program Files (x86)\ossec-agent"
    )
    
    $results = @{
        ConfigExists = $false
        ConfigValid = $false
        AgentRunning = $false
        ManagerConnection = $false
    }
    
    # Check config file
    $configPath = Join-Path $WazuhPath "ossec.conf"
    $results.ConfigExists = Test-Path $configPath
    
    if ($results.ConfigExists) {
        try {
            # Validate config using Wazuh agent
            $validateOutput = & "$WazuhPath\ossec-agent.exe" -t 2>&1
            $results.ConfigValid = $validateOutput -match "OK"
        } catch {
            $results.ConfigValid = $false
        }
    }
    
    # Check agent status
    $agentService = Get-Service -Name "Wazuh" -ErrorAction SilentlyContinue
    $results.AgentRunning = $agentService.Status -eq "Running"
    
    # Test manager connection
    if ($results.AgentRunning) {
        $results.ManagerConnection = Test-Port -Port 1514
    }
    
    return $results
}

function Restart-SOCServices {
    param(
        [switch]$Wazuh,
        [switch]$Elastic,
        [switch]$Kibana,
        [switch]$Logstash,
        [switch]$All
    )
    
    $services = @()
    
    if ($Wazuh -or $All) {
        $services += "Wazuh"
    }
    if ($Elastic -or $All) {
        $services += "elasticsearch-service-x64"
    }
    if ($Kibana -or $All) {
        $services += "kibana"
    }
    if ($Logstash -or $All) {
        $services += "logstash"
    }
    
    foreach ($service in $services) {
        try {
            Restart-Service -Name $service -Force
            Write-Host "Successfully restarted $service"
        } catch {
            Write-Error "Failed to restart $service: $_"
        }
    }
}

function Get-SOCStatus {
    $status = @{
        Timestamp = Get-Date
        Services = @{}
        Containers = @{}
        Ports = @{}
        ElasticHealth = $null
    }
    
    # Check services
    $services = @("Wazuh", "elasticsearch-service-x64", "kibana", "logstash")
    foreach ($service in $services) {
        $status.Services[$service] = Get-ServiceStatus -ServiceName $service
    }
    
    # Check containers
    $containers = @("shuffle-backend", "shuffle-frontend")
    foreach ($container in $containers) {
        $status.Containers[$container] = Test-DockerContainer -ContainerName $container
    }
    
    # Check ports
    $ports = @(
        @{Name = "Wazuh Manager"; Port = 1514},
        @{Name = "Elasticsearch"; Port = 9200},
        @{Name = "Kibana"; Port = 5601},
        @{Name = "Logstash"; Port = 5044}
    )
    
    foreach ($portInfo in $ports) {
        $status.Ports[$portInfo.Name] = Test-Port -Port $portInfo.Port
    }
    
    # Get Elasticsearch health
    $status.ElasticHealth = Get-ElasticsearchHealth
    
    return $status
}

# Export functions
Export-ModuleMember -Function *