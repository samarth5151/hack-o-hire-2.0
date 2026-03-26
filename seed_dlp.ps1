$api = "http://localhost:8001/gateway/analyze"

$prompts = @(
    @{ user_id="alice@barclays.com"; department="finance"; role="analyst"; prompt="My AWS key is AKIAJSIE27KKMHXI3BJQ secret=wJalrXUtnFEMI/K7MDENG/bPxRfiCY"; destination_model="chatgpt" },
    @{ user_id="bob@barclays.com"; department="hr"; role="manager"; prompt="Employee NI AB123456C salary=95000 for performance review"; destination_model="claude" },
    @{ user_id="alice@barclays.com"; department="finance"; role="analyst"; prompt="Transfer GBP to IBAN GB82 WEST 1234 5698 7654 32"; destination_model="chatgpt" },
    @{ user_id="charlie@barclays.com"; department="legal"; role="analyst"; prompt="STRICTLY CONFIDENTIAL: Board merger notes acquisition for 2B USD"; destination_model="gemini" },
    @{ user_id="dave@barclays.com"; department="tech"; role="developer"; prompt="Help me write a SQL query to find top customers"; destination_model="chatgpt" },
    @{ user_id="alice@barclays.com"; department="finance"; role="analyst"; prompt="Card number 4532015112830366 CVV 372 expiry 12/26 for payment processing"; destination_model="chatgpt" },
    @{ user_id="eve@barclays.com"; department="ops"; role="analyst"; prompt="What is compound interest and how is it calculated?"; destination_model="claude" },
    @{ user_id="bob@barclays.com"; department="hr"; role="manager"; prompt="Payroll data: salary=120000 bonus=45000 for employee 00456"; destination_model="gemini" },
    @{ user_id="frank@barclays.com"; department="risk"; role="analyst"; prompt="Aadhaar 2345 6789 0123 PAN ABCDE1234F for KYC verification"; destination_model="chatgpt" },
    @{ user_id="dave@barclays.com"; department="tech"; role="developer"; prompt="Explain the difference between REST and GraphQL APIs"; destination_model="chatgpt" },
    @{ user_id="charlie@barclays.com"; department="legal"; role="analyst"; prompt="GitHub PAT: ghp_1A2B3C4D5E6F7G8H9I0J1K2L3M4N5O6P7Q8R9 for deployment"; destination_model="claude" },
    @{ user_id="grace@barclays.com"; department="finance"; role="senior_analyst"; prompt="How do I implement pagination in FastAPI?"; destination_model="gemini" },
    @{ user_id="alice@barclays.com"; department="finance"; role="analyst"; prompt="BARCLAYS INTERNAL Q3 revenue was 2.3B profits down 12 percent do not share"; destination_model="chatgpt" },
    @{ user_id="henry@barclays.com"; department="compliance"; role="officer"; prompt="US SSN 123-45-6789 for employee insurance claim processing"; destination_model="claude" },
    @{ user_id="dave@barclays.com"; department="tech"; role="developer"; prompt="What are best practices for Docker container security?"; destination_model="chatgpt" }
)

foreach ($p in $prompts) {
    $body = $p | ConvertTo-Json
    try {
        $r = Invoke-WebRequest -Uri $api -Method POST -Body $body -ContentType "application/json" -UseBasicParsing
        $data = $r.Content | ConvertFrom-Json
        Write-Host "[$($data.decision)] $($p.user_id) -> $($p.destination_model)"
    } catch {
        Write-Host "ERROR: $_"
    }
    Start-Sleep -Milliseconds 200
}

Write-Host "`nSeeding complete. Refresh the DLP Guardian dashboard."
