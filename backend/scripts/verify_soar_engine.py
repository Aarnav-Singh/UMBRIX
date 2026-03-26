import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.services.soar.engine import ExecutionEngine, Playbook

# Register mock provider
from app.services.soar.actions import ActionRegistry, ActionProvider
class MockProvider(ActionProvider):
    name = 'test_provider'
    async def execute(self, action_type: str, params: dict):
        print(f'Execute {action_type} with params {params}')
        return 'completed'
ActionRegistry.providers['test_provider'] = MockProvider()

async def main():
    engine = ExecutionEngine()
    
    pb_data = {
        'id': 'pb_cond_test',
        'name': 'Test Cond',
        'nodes': [
            {
                'id': 'cond_node',
                'action_type': 'conditional',
                'provider': 'builtin',
                'params': {
                    'condition': '{{ severity >= 3 }}'
                },
                'on_true': [
                    {
                        'id': 'true_node',
                        'action_type': 'test_action',
                        'provider': 'test_provider',
                        'params': {'message': 'Severity is {{ severity }}!'}
                    }
                ],
                'on_false': [
                    {
                        'id': 'false_node',
                        'action_type': 'test_action',
                        'provider': 'test_provider',
                        'params': {'message': 'All good, severity {{ severity }}'}
                    }
                ]
            }
        ]
    }
    
    pb = Playbook(**pb_data)

    passed = 0
    failed = 0

    print('\\nTest 1: Severity 4 (True branch expected)')
    ctx1 = {'severity': 4}
    res1 = await engine.execute_playbook(pb, ctx1)
    
    # Check if true_node was executed
    true_executed = any(r['node_id'] == 'true_node' for r in res1)
    if true_executed and any("Severity is 4!" in r['params'].get('message', '') for r in res1 if r['node_id'] == 'true_node'):
        print("[PASS] Condition True -> on_true branch taken and param templated.")
        passed += 1
    else:
        print(f"[FAIL] Condition True didn't work. Results: {res1}")
        failed += 1
    
    print('\\nTest 2: Severity 2 (False branch expected)')
    ctx2 = {'severity': 2}
    res2 = await engine.execute_playbook(pb, ctx2)

    false_executed = any(r['node_id'] == 'false_node' for r in res2)
    if false_executed and any("severity 2" in r['params'].get('message', '') for r in res2 if r['node_id'] == 'false_node'):
        print("[PASS] Condition False -> on_false branch taken and param templated.")
        passed += 1
    else:
        print(f"[FAIL] Condition False didn't work. Results: {res2}")
        failed += 1

    print(f"\\nResults: {passed} passed, {failed} failed")

if __name__ == "__main__":
    asyncio.run(main())
