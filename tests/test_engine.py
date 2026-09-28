import sys
from pathlib import Path

# Add project root to sys.path for cross-environment module resolution
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from modules.engine import ThreatEngine
from modules.hasher import calculate_sha256, calculate_entropy, defang_string, refang_string

SAMPLES_DIR = Path(__file__).resolve().parent / "samples"

@pytest.fixture
def engine():
    """Pytest fixture initializing the threat detection engine."""
    return ThreatEngine()

def test_benign_sample(engine):
    """Verify that a standard clean system log evaluates to LOW risk (score < 30)."""
    benign_path = SAMPLES_DIR / "sample_benign.txt"
    assert benign_path.exists(), "sample_benign.txt sample file missing"
    
    with open(benign_path, "r", encoding="utf-8") as f:
        content = f.read()
        
    results = engine.analyze(content, filename="sample_benign.txt")
    
    assert results["score"] < 30, f"Expected score < 30 for benign sample, got {results['score']}"
    assert results["risk_level"] == "LOW", f"Expected LOW risk level, got {results['risk_level']}"
    assert len(results["matched_iocs"]) == 0

def test_clickfix_detection(engine):
    """Verify that ClickFix obfuscated script lure triggers PowerShell T1059.001 & T1204.002."""
    clickfix_path = SAMPLES_DIR / "sample_clickfix.ps1"
    assert clickfix_path.exists(), "sample_clickfix.ps1 sample file missing"
    
    with open(clickfix_path, "r", encoding="utf-8") as f:
        content = f.read()
        
    results = engine.analyze(content, filename="sample_clickfix.ps1")
    
    mitre_ids = [m["id"] for m in results["mitre_mappings"]]
    assert "T1059.001" in mitre_ids, "Expected MITRE T1059.001 (PowerShell Scripting)"
    assert "T1204.002" in mitre_ids, "Expected MITRE T1204.002 (ClickFix User Execution)"
    assert results["score"] >= 20

def test_recon_detection(engine):
    """Verify that secondary VBS recon script flags discovery commands (T1082, T1057, T1083)."""
    recon_path = SAMPLES_DIR / "sample_recon.vbs"
    assert recon_path.exists(), "sample_recon.vbs sample file missing"
    
    with open(recon_path, "r", encoding="utf-8") as f:
        content = f.read()
        
    results = engine.analyze(content, filename="sample_recon.vbs")
    
    mitre_ids = [m["id"] for m in results["mitre_mappings"]]
    assert any(tid in mitre_ids for tid in ["T1082", "T1057", "T1083"]), "Expected discovery MITRE techniques"
    assert any(s["rule"] == "Host_Network_Reconnaissance" for s in results["signals"])
    assert results["score"] >= 30

def test_full_attack_chain(engine):
    """Verify full COLDRIVER LOSTKEYS attack log scores >= 80 (CRITICAL) & triggers correlation bonus."""
    full_attack_path = SAMPLES_DIR / "sample_full_attack.log"
    assert full_attack_path.exists(), "sample_full_attack.log sample file missing"
    
    with open(full_attack_path, "r", encoding="utf-8") as f:
        content = f.read()
        
    results = engine.analyze(content, filename="sample_full_attack.log")
    
    assert results["score"] >= 80, f"Expected CRITICAL score >= 80, got {results['score']}"
    assert results["risk_level"] == "CRITICAL"
    
    # Assert multi-signal correlation bonus was activated
    signal_rules = [s["rule"] for s in results["signals"]]
    assert "Multi_Signal_Correlation_Bonus" in signal_rules, "Multi-signal correlation bonus failed to activate"
    assert len(results["matched_iocs"]) > 0

def test_hashing_and_entropy():
    """Verify SHA-256 calculation and entropy function against known deterministic values."""
    sample_text = "LOSTKEYS Threat Detector Synthetic Test Payload"
    expected_hash = "c8b97e32d156e7d165212b9068d6fcf9272a768b2c64f690b170be57c85b6856"
    
    calculated_hash = calculate_sha256(sample_text)
    assert calculated_hash == expected_hash, f"Hash mismatch: expected {expected_hash}, got {calculated_hash}"
    
    entropy_val = calculate_entropy(sample_text)
    assert 0.0 <= entropy_val <= 8.0, "Entropy out of valid range [0, 8]"
    
    # Check defang / refang utility
    raw_domain = "cloudmediaportal.com"
    defanged = defang_string(raw_domain)
    assert "[.]com" in defanged
    assert refang_string(defanged) == raw_domain
