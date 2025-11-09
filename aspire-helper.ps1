# PowerShell script for .NET Aspire setup and management

param(
    [string]$Command = "help"
)

function Show-Help {
    Write-Host ".NET Aspire SMTP Server Helper" -ForegroundColor Green
    Write-Host "================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Available commands:" -ForegroundColor Yellow
    Write-Host "  install-aspire  - Install .NET Aspire workload"
    Write-Host "  check-prereqs   - Check prerequisites (Docker, .NET 9)"
    Write-Host "  run-aspire      - Run the Aspire application"
    Write-Host "  open-dashboard  - Open Aspire dashboard in browser"
    Write-Host "  check-docker    - Check Docker Desktop status"
    Write-Host "  clean-aspire    - Clean Aspire containers and images"
    Write-Host "  help           - Show this help"
    Write-Host ""
    Write-Host "Example usage:" -ForegroundColor Cyan
    Write-Host "  .\aspire-helper.ps1 install-aspire"
    Write-Host "  .\aspire-helper.ps1 run-aspire"
    Write-Host "  .\aspire-helper.ps1 open-dashboard"
}

function Install-Aspire {
    Write-Host "Installing .NET Aspire workload..." -ForegroundColor Green
    
    # Update workloads
    Write-Host "Updating .NET workloads..." -ForegroundColor Cyan
    dotnet workload update
    
    # Install Aspire workload
    Write-Host "Installing Aspire workload..." -ForegroundColor Cyan
    dotnet workload install aspire
    
    Write-Host "Aspire workload installed successfully!" -ForegroundColor Green
}

function Check-Prerequisites {
    Write-Host "Checking prerequisites..." -ForegroundColor Green
    
    # Check .NET version
    Write-Host "Checking .NET version..." -ForegroundColor Cyan
    $dotnetVersion = dotnet --version
    Write-Host "  .NET Version: $dotnetVersion" -ForegroundColor White
    
    if ($dotnetVersion -lt "9.0") {
        Write-Host "  ??  .NET 9.0 or later is required" -ForegroundColor Yellow
    } else {
        Write-Host "  ? .NET version is compatible" -ForegroundColor Green
    }
    
    # Check Docker
    Write-Host "Checking Docker..." -ForegroundColor Cyan
    try {
        $dockerVersion = docker --version
        Write-Host "  Docker Version: $dockerVersion" -ForegroundColor White
        Write-Host "  ? Docker is available" -ForegroundColor Green
    }
    catch {
        Write-Host "  ? Docker not found or not running" -ForegroundColor Red
        Write-Host "  Please install Docker Desktop and ensure it's running" -ForegroundColor Yellow
    }
    
    # Check Aspire workload
    Write-Host "Checking Aspire workload..." -ForegroundColor Cyan
    $workloads = dotnet workload list
    if ($workloads -match "aspire") {
        Write-Host "  ? Aspire workload is installed" -ForegroundColor Green
    } else {
        Write-Host "  ? Aspire workload not installed" -ForegroundColor Red
        Write-Host "  Run: .\aspire-helper.ps1 install-aspire" -ForegroundColor Yellow
    }
}

function Run-Aspire {
    Write-Host "Starting .NET Aspire application..." -ForegroundColor Green
    Write-Host "This will start:" -ForegroundColor Cyan
    Write-Host "  - Aspire Dashboard" -ForegroundColor White
    Write-Host "  - Azurite Storage Emulator" -ForegroundColor White
    Write-Host "  - Blazor Web Application" -ForegroundColor White
    Write-Host "  - SMTP Server Service" -ForegroundColor White
    Write-Host ""
    
    # Change to AppHost directory and run
    Set-Location "BlazorSMTPServer.AppHost"
    dotnet run
}

function Open-Dashboard {
    Write-Host "Opening Aspire Dashboard..." -ForegroundColor Green
    
    # Default Aspire dashboard URL
    $dashboardUrl = "https://localhost:15888"
    
    try {
        Start-Process $dashboardUrl
        Write-Host "Dashboard should open in your default browser" -ForegroundColor Green
        Write-Host "URL: $dashboardUrl" -ForegroundColor Cyan
    }
    catch {
        Write-Host "Could not automatically open browser" -ForegroundColor Yellow
        Write-Host "Please manually navigate to: $dashboardUrl" -ForegroundColor Cyan
    }
}

function Check-Docker {
    Write-Host "Checking Docker Desktop status..." -ForegroundColor Green
    
    try {
        $dockerInfo = docker info 2>$null
        Write-Host "? Docker Desktop is running" -ForegroundColor Green
        
        # Check for Aspire/Azurite containers
        Write-Host "Checking Aspire containers..." -ForegroundColor Cyan
        $containers = docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
        
        if ($containers -match "azurite") {
            Write-Host "Azurite containers:" -ForegroundColor White
            $containers | Select-String "azurite"
        } else {
            Write-Host "No Azurite containers running" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "? Docker Desktop is not running" -ForegroundColor Red
        Write-Host "Please start Docker Desktop before running Aspire" -ForegroundColor Yellow
    }
}

function Clean-Aspire {
    Write-Host "Cleaning Aspire containers and images..." -ForegroundColor Green
    
    # Stop and remove Aspire containers
    Write-Host "Stopping Aspire containers..." -ForegroundColor Cyan
    docker stop $(docker ps -q --filter "label=aspire") 2>$null
    
    Write-Host "Removing Aspire containers..." -ForegroundColor Cyan
    docker rm $(docker ps -aq --filter "label=aspire") 2>$null
    
    # Remove Azurite containers specifically
    Write-Host "Cleaning Azurite containers..." -ForegroundColor Cyan
    docker stop $(docker ps -q --filter "ancestor=mcr.microsoft.com/azure-storage/azurite") 2>$null
    docker rm $(docker ps -aq --filter "ancestor=mcr.microsoft.com/azure-storage/azurite") 2>$null
    
    # Clean up Docker system
    Write-Host "Cleaning Docker system..." -ForegroundColor Cyan
    docker system prune -f
    
    Write-Host "Aspire cleanup completed!" -ForegroundColor Green
}

# Main script logic
switch ($Command.ToLower()) {
    "install-aspire" { Install-Aspire }
    "check-prereqs" { Check-Prerequisites }
    "run-aspire" { Run-Aspire }
    "open-dashboard" { Open-Dashboard }
    "check-docker" { Check-Docker }
    "clean-aspire" { Clean-Aspire }
    "help" { Show-Help }
    default { 
        Write-Host "Unknown command: $Command" -ForegroundColor Red
        Show-Help 
    }
}