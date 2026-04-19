import { test, expect } from '@playwright/test';

test.describe('ML Pipeline Dashboard — Layout Verification', () => {
    test.beforeEach(async ({ page }) => {
        // Navigate to the pipeline page
        await page.goto('/pipeline');
        // Wait for potential animations/data fetching
        await page.waitForTimeout(1000);
    });

    test('should render HUD and all high-level components', async ({ page }) => {
        await expect(page.getByText('Global Inference Topology')).toBeVisible({ timeout: 20000 });
        const panel = page.getByTestId('pipeline-topology-visualizer');
        await expect(panel.first()).toBeAttached();
        await expect(page.getByTestId('model-registry-panel')).toBeVisible();
        await expect(page.getByTestId('signal-matrix-panel')).toBeVisible();
        await expect(page.getByTestId('neural-debug-panel')).toBeVisible();
    });

    test('should display all 4 primary KPI cards', async ({ page }) => {
        const kpiTestIds = [
            'kpi-card-avg-latency',
            'kpi-card-avg-accuracy',
            'kpi-card-models-serving',
            'kpi-card-events-processed'
        ];

        for (const testId of kpiTestIds) {
            await expect(page.getByTestId(testId)).toBeVisible();
        }
    });

    test('should verify topology nodes are spread across the workspace', async ({ page }) => {
        const nodes = page.locator('[data-testid="topology-node"]');
        await nodes.first().waitFor();
        const count = await nodes.count();
        expect(count).toBeGreaterThan(0);

        const boxes = [];
        for (let i = 0; i < count; i++) {
            const box = await nodes.nth(i).boundingBox();
            if (box) {
                boxes.push({ id: await nodes.nth(i).getAttribute('data-node-id'), ...box });
            }
        }

        // Verify spread (min/max X coordinates)
        const xCoords = boxes.map(b => b.x);
        const minX = Math.min(...xCoords);
        const maxX = Math.max(...xCoords);
        const viewport = page.viewportSize();
        const containerWidth = viewport ? viewport.width : 1280;

        // Nodes should be spread at least across 50% of the viewport width (taking into account sidebar and padding)
        expect(maxX - minX).toBeGreaterThan(containerWidth * 0.5);

        // Check for node overlap
        for (let i = 0; i < boxes.length; i++) {
            for (let j = i + 1; j < boxes.length; j++) {
                const b1 = boxes[i];
                const b2 = boxes[j];

                const overlapX = Math.max(0, Math.min(b1.x + b1.width, b2.x + b2.width) - Math.max(b1.x, b2.x));
                const overlapY = Math.max(0, Math.min(b1.y + b1.height, b2.y + b2.height) - Math.max(b1.y, b2.y));
                const overlapArea = overlapX * overlapY;

                const minArea = Math.min(b1.width * b1.height, b2.width * b2.height);
                // Allow up to 15% overlap for safety (e.g. glowing halos)
                expect(overlapArea / minArea, `Node overlap too high between ${b1.id} and ${b2.id}`).toBeLessThan(0.15);
            }
        }
    });
});
