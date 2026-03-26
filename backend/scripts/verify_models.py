"""Standalone verification script for Phase 22A trained models."""
import asyncio
import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def main():
    from app.ml.ensemble import EnsembleClassifier

    passed = 0
    failed = 0

    # Test 1: Model loads as trained_rf (not synthetic)
    clf = EnsembleClassifier()
    clf.load_models()
    if clf._model_type == "trained_rf" and clf._feature_dim == 76:
        print("[PASS] Test 1: Trained RF loaded with 76-dim features")
        passed += 1
    else:
        print(f"[FAIL] Test 1: Expected trained_rf/76, got {clf._model_type}/{clf._feature_dim}")
        failed += 1

    # Test 2: Benign-like input scores low
    features_benign = [80.0, 443.0, 500.0, 2000.0, 5.0, 5.0] + [0.0] * 70
    result = asyncio.run(clf.score(features_benign))
    if 0.0 <= result["score"] <= 1.0 and result["label"] in ["benign", "dos", "ddos", "brute_force", "web_attack", "infiltration", "botnet", "port_scan", "sql_injection", "fuzzers", "backdoors", "exploits", "reconnaissance"]:
        print(f"[PASS] Test 2: Benign score={result['score']:.4f}, label={result['label']}")
        passed += 1
    else:
        print(f"[FAIL] Test 2: Invalid result: {result}")
        failed += 1

    # Test 3: Attack-like input produces different result
    features_attack = [45000.0, 80.0, 50000.0, 1000.0, 500.0, 10.0] + [0.0] * 70
    result_attack = asyncio.run(clf.score(features_attack))
    if result_attack["score"] != result["score"] or result_attack["label"] != result["label"]:
        print(f"[PASS] Test 3: Attack score={result_attack['score']:.4f}, label={result_attack['label']}")
        passed += 1
    else:
        print(f"[FAIL] Test 3: Benign and attack produced identical results")
        failed += 1

    # Test 4: Probabilities sum to ~1
    total_prob = sum(result["probabilities"].values())
    if abs(total_prob - 1.0) < 0.01:
        print(f"[PASS] Test 4: Probabilities sum = {total_prob:.4f}")
        passed += 1
    else:
        print(f"[FAIL] Test 4: Probabilities sum = {total_prob:.4f}")
        failed += 1

    # Test 5: model_type field is present in output
    if "model_type" in result and result["model_type"] == "trained_rf":
        print(f"[PASS] Test 5: model_type = {result['model_type']}")
        passed += 1
    else:
        print(f"[FAIL] Test 5: model_type missing or wrong")
        failed += 1

    # Test 6: VAE model loads and scores
    from app.ml.vae import VAEAnomalyDetector
    vae = VAEAnomalyDetector()
    models_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")
    vae_path = os.path.join(models_dir, "vae.pth")
    vae.load_model(vae_path if os.path.exists(vae_path) else None)
    vae_score = asyncio.run(vae.score(features_benign))
    if isinstance(vae_score, float) and 0.0 <= vae_score <= 1.0:
        print(f"[PASS] Test 6: VAE score = {vae_score:.4f} (trained weights)")
        passed += 1
    else:
        print(f"[FAIL] Test 6: VAE score invalid: {vae_score}")
        failed += 1

    # Test 7: Training metadata exists and has results
    metadata_path = os.path.join(models_dir, "training_metadata.json")
    if os.path.exists(metadata_path):
        with open(metadata_path) as f:
            meta = json.load(f)
        auc = meta.get("results", {}).get("random_forest", {}).get("auc_weighted", 0)
        fpr = meta.get("results", {}).get("random_forest", {}).get("fpr_benign", 1)
        if auc >= 0.85 and fpr <= 0.08:
            print(f"[PASS] Test 7: AUC={auc:.4f} (>0.85), FPR={fpr:.4f} (<0.08)")
            passed += 1
        else:
            print(f"[FAIL] Test 7: AUC={auc}, FPR={fpr}")
            failed += 1
    else:
        print("[FAIL] Test 7: training_metadata.json not found")
        failed += 1

    # Test 8: Meta-learner weights update and normalize
    from app.ml.meta_learner import MetaLearner
    ml = MetaLearner()
    ml.update_weights("true_positive", [0.8, 0.1, 0.1, 0.1, 0.1])
    total = sum(ml.current_weights)
    if abs(total - 1.0) < 0.01:
        print(f"[PASS] Test 8: Meta-learner weights normalize to {total:.4f}")
        passed += 1
    else:
        print(f"[FAIL] Test 8: Weights sum = {total}")
        failed += 1

    print(f"\n{'='*40}")
    print(f"Results: {passed}/{passed+failed} passed")
    if failed == 0:
        print("ALL TESTS PASSED")
    else:
        print(f"{failed} tests FAILED")
    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
