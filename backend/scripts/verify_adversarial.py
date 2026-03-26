"""Standalone verification for Phase 23C: Adversarial Detection."""
import asyncio
import sys
import os
import random

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.ml.adversarial import AdversarialDetector

async def main():
    det = AdversarialDetector()
    det.load_model(None)  # Random init activates full 4-stream scoring
    
    print("Phase 23C Verification: Adversarial Detector")
    print("-" * 50)
    
    passed = 0
    failed = 0
    
    # 1. Test Timing: Highly regular (automated beaconing)
    # 500ms fixed interval
    for i in range(20):
        score_auto = await det.score("ent_auto", i * 500, 0, 0, 0)
        
    if score_auto["timing_score"] > 0.8:
        print(f"[PASS] 1. Automated timing detected (score={score_auto['timing_score']:.4f})")
        passed += 1
    else:
        print(f"[FAIL] 1. Automated timing missed (score={score_auto['timing_score']:.4f})")
        failed += 1
        
    # 2. Test Timing: Random human-like (exponential)
    ts = 0
    random.seed(42)
    for i in range(30):
        ts += random.expovariate(1.0/500.0)
        score_human = await det.score("ent_human", ts, 0, 0, 0)
        
    if score_human["timing_score"] < 0.2:
        print(f"[PASS] 2. Human timing allowed (score={score_human['timing_score']:.4f})")
        passed += 1
    else:
        print(f"[FAIL] 2. Human timing flagged (score={score_human['timing_score']:.4f})")
        failed += 1
        
    # 3. Test OOD: Normal features
    normal_feat = [0.0] * 256
    score_normal = await det.score("ent_ood1", 0, 0, 0, 0, normal_feat)
    
    if score_normal["ood_score"] < 0.1:
        print(f"[PASS] 3. Normal features allowed (score={score_normal['ood_score']:.4f})")
        passed += 1
    else:
        print(f"[FAIL] 3. Normal features flagged (score={score_normal['ood_score']:.4f})")
        failed += 1
        
    # 4. Test OOD: Anomalous features
    # Baseline expected distance is sqrt(256)=16. 
    # Features of 5.0 scaled by cov^-1 (which is 10.0 since cov=0.1*I) -> distance is very high
    anom_feat = [5.0] * 256
    score_anom = await det.score("ent_ood2", 0, 0, 0, 0, anom_feat)
    
    if score_anom["ood_score"] > 0.9:
        print(f"[PASS] 4. OOD features detected (score={score_anom['ood_score']:.4f})")
        passed += 1
    else:
        print(f"[FAIL] 4. OOD features missed (score={score_anom['ood_score']:.4f})")
        failed += 1
        
    print(f"\nResults: {passed} passed, {failed} failed")
    
    return failed == 0

if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)
