import json
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
    page.locator('#config-dialog .primary').click()
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
    demo['mode'] = 'live'
    demo['managed_vmids'] = [101]
    upid = 'UPID:homeserver:00000000:00000000:00000000:vzstart:101:nerv@pve!panel:'
    requests = []

    def accept_power(route):
        requests.append((route.request.method, route.request.headers.get('x-nerv-action')))
        route.fulfill(status=202, json={'upid': upid})

    page.route('**/api/status', lambda route: route.fulfill(json=demo))
    page.route('**/api/guests/101/start', accept_power)
    page.route('**/api/power-tasks/**', lambda route: route.fulfill(json={'status': 'stopped', 'exitstatus': 'OK'}))
    page.locator('#refresh').click()
    page.locator('#guest-search').fill('101')
    page.select_option('#guest-type', 'lxc')
    assert page.locator('#guests tr').count() == 1
    start_button = page.get_by_role('button', name='Запустить Media · пример')
    start_button.click()
    page.get_by_role('button', name='Отмена', exact=True).click()
    assert not requests
    start_button.click()
    page.get_by_role('button', name='Подтвердить', exact=True).click()
    page.get_by_text('Media · пример · операция выполнена.').wait_for()
    assert requests == [('POST', 'guest-power')]
    assert not errors, errors
    browser.close()
print('Browser checks passed: filtering, theme persistence, dialog, API failure/recovery, mobile overflow, no JS errors.')
