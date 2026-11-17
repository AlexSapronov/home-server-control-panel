from pathlib import Path
Path("docs").mkdir(exist_ok=True)
from playwright.sync_api import sync_playwright
with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page=browser.new_page(viewport={'width':1440,'height':1080}, device_scale_factor=1)
    errors=[]
    page.on('pageerror', lambda error: errors.append(str(error)))
    page.goto('http://127.0.0.1:8080')
    page.wait_for_selector('#guests tr')
    page.screenshot(path='docs/dashboard.png', full_page=True)
    assert 'DEMO MODE' in page.locator('#mode').inner_text()
    page.select_option('#guest-filter', 'stopped')
    assert page.locator('#guests tr').count()==1
    assert 'Media' in page.locator('#guests').inner_text()
    page.select_option('#theme','EVA-01')
    page.reload()
    assert page.locator('body').get_attribute('data-theme')=='EVA-01'
    page.locator('#settings').click()
    assert page.locator('#config-dialog').is_visible()
    page.locator('.primary').click()
    page.route('**/api/status',lambda route:route.fulfill(status=502,content_type='application/json',body='{"error":"Test offline"}'))
    page.locator('#refresh').click()
    page.locator("body.stale").wait_for(state="attached")
    assert 'устаревшие' in page.locator('#error').inner_text()
    page.unroute('**/api/status')
    page.locator('#refresh').click()
    page.locator("body.stale").wait_for(state="detached")
    page.set_viewport_size({'width':390,'height':844})
    page.select_option('#theme','NERV')
    page.screenshot(path='docs/mobile.png',full_page=True)
    assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
    assert not errors, errors
    browser.close()
print('Browser checks passed: filtering, theme persistence, dialog, API failure/recovery, mobile overflow, no JS errors.')
