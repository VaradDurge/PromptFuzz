"""Probe pict.edu to find the Dialogflow Messenger structure."""
import asyncio
from playwright.async_api import async_playwright

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)


async def main():
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=False)
        context = await browser.new_context(
            user_agent=USER_AGENT,
            viewport={"width": 1366, "height": 768},
        )
        page = await context.new_page()

        print("Navigating to https://pict.edu ...")
        await page.goto("https://pict.edu", wait_until="domcontentloaded", timeout=60000)
        print("domcontentloaded. Waiting 10s for all scripts...")
        await page.wait_for_timeout(10000)

        # 1. Check for df-messenger directly on page
        df = await page.evaluate("() => !!document.querySelector('df-messenger')")
        print(f"\ndf-messenger on main page: {df}")

        # 2. Check all iframes for df-messenger
        frames = page.frames
        print(f"Total frames on page: {len(frames)}")
        for i, frame in enumerate(frames):
            try:
                url = frame.url
                has_df = await frame.evaluate("() => !!document.querySelector('df-messenger')")
                print(f"  Frame {i}: {url[:80]} | df-messenger: {has_df}")
            except Exception:
                print(f"  Frame {i}: (could not evaluate)")

        # 3. Check what custom elements are registered
        custom_elements = await page.evaluate("""
        () => {
            var tags = [];
            document.querySelectorAll('*').forEach(function(el) {
                if (el.tagName.includes('-')) tags.push(el.tagName.toLowerCase());
            });
            return [...new Set(tags)];
        }
        """)
        print(f"\nCustom elements found: {custom_elements}")

        # 4. Scroll down to trigger lazy loading then recheck
        print("\nScrolling page to trigger lazy load...")
        await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
        await page.wait_for_timeout(3000)
        await page.evaluate("window.scrollTo(0, 0)")
        await page.wait_for_timeout(2000)

        df_after_scroll = await page.evaluate("() => !!document.querySelector('df-messenger')")
        print(f"df-messenger after scroll: {df_after_scroll}")

        # 5. If still not found, dump all script srcs to find dialogflow scripts
        if not df_after_scroll:
            scripts = await page.evaluate("""
            () => Array.from(document.scripts)
                .map(function(s) { return s.src; })
                .filter(function(s) { return s.length > 0; })
            """)
            df_scripts = [s for s in scripts if "dialogflow" in s.lower() or "df-messenger" in s.lower()]
            print(f"\nDialogflow-related scripts: {df_scripts}")
            print(f"All script srcs ({len(scripts)} total): first 10:")
            for s in scripts[:10]:
                print(f"  {s}")

        print("\nDone. Browser stays open for 15s so you can inspect...")
        await page.wait_for_timeout(15000)
        await browser.close()


asyncio.run(main())
