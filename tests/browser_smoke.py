import json
import os
from pathlib import Path
Path("docs").mkdir(exist_ok=True)
from playwright.sync_api import sync_playwright
with sync_playwright() as p:
    browser = p.chromium.launch(headless=True, executable_path=os.environ.get('NERV_BROWSER_PATH'))
    page=browser.new_page(viewport={'width':1440,'height':1080}, device_scale_factor=1)
    errors=[]
    page.on('pageerror', lambda error: errors.append(str(error)))
    page.goto('http://127.0.0.1:8080')
    page.wait_for_selector('#guests tr')
    assert page.locator('#router-cards article').count()==4
    assert 'Не настроен' in page.locator('#router-cards').inner_text()
    assert 'Имя разрешено' in page.locator('#router-probes').inner_text()
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
    demo=page.request.get('http://127.0.0.1:8080/api/status').json()
    demo['router']['state']='unavailable'
    demo['router']['stale']=True
    demo['router']['error']='SSH unavailable'
    page.route('**/api/status', lambda route:route.fulfill(status=200,content_type='application/json',body=json.dumps(demo)))
    page.locator('#refresh').click()
    page.locator('#router-cards.router-stale').wait_for(state='attached')
    assert 'устаревшие' in page.locator('#router-notice').inner_text()
    assert 'Имя разрешено' in page.locator('#router-probes').inner_text()
    page.unroute('**/api/status')
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
    assert not page.locator('#dpi').is_visible()
    submitted = []
    dpi = {
        'enabled': True, 'router_online': True, 'lan_online': True, 'router': {'previous': None},
        'operation': None, 'last_operation': None, 'jobs': [], 'versions': [{
            'id': 'a' * 64, 'profile': 'youtube', 'delivered': 1780000000, 'expires': 1780172800,
            'eligible': True, 'rule': {'domains': ['youtube.com'], 'args': ['--dpi-desync=fake']},
        }],
        'profiles': {'youtube': {
            'active': {'domains': ['youtube.com'], 'args': ['--dpi-desync=multidisorder']},
            'active_score': [3, 3], 'automatic': False, 'last_check': 1780000000, 'next_revision': 1780604800,
        }},
    }

    def add_job(route):
        assert route.request.headers['x-nerv-request'] == 'dpi'
        data = route.request.post_data_json
        submitted.append(data['url'])
        dpi['jobs'].append({'id': '123', 'profile': 'example.net', 'kind': 'search', 'state': 'queued',
                            'created': 1780000000})
        route.fulfill(status=200, json={'id': '123'})

    page.route('**/api/dpi', lambda route: route.fulfill(status=200, json=dpi))
    page.route('**/api/dpi/admin/add', add_job)
    page.reload()
    page.get_by_role('link', name='07 Стратегии DPI').click()
    page.get_by_label('Адрес сайта').fill('https://example.net/a')
    page.get_by_role('button', name='Подобрать стратегию').click()
    page.get_by_text('Отправка…').wait_for(state='hidden')
    assert submitted == ['https://example.net/a']
    page.get_by_text('example.net · Подбор · В очереди').wait_for()
    assert page.get_by_role('button', name='Применить на OpenWrt').is_enabled()
    assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
    assert not errors, errors
    browser.close()
print('Browser checks passed: filtering, theme persistence, dialog, API failure/recovery, DPI submission and delivery state, mobile overflow, no JS errors.')
