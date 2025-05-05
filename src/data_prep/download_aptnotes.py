import os
import hashlib
import asyncio
import aiohttp
import platform
import glob
import json
import magic
import requests

from bs4 import BeautifulSoup
from pathlib import Path

def get_download_url(page):
    soup = BeautifulSoup(page, 'lxml')
    scripts = soup.find('body').find_all('script')
    sections = scripts[-1].contents[0].split(';')
    app_api = json.loads(sections[0].split('=')[1])['/app-api/enduserapp/shared-item']
    box_url = "https://app.box.com/index.php"
    box_args = "?rm=box_download_shared_file&shared_name={}&file_id={}"
    return box_url + box_args.format(app_api['sharedName'], f"f_{app_api['itemID']}")

def load_notes():
    github_url = "https://raw.githubusercontent.com/aptnotes/data/master/APTnotes.json"
    APTnotes = requests.get(github_url)
    return list(reversed(json.loads(APTnotes.text))) if APTnotes.status_code == 200 else []

supported_filetypes = {
    "application/pdf": ".pdf",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx"
}

def verify_report_filetype(download_path):
    file_type = magic.from_file(download_path, mime=True)
    if file_type in supported_filetypes and not download_path.endswith(supported_filetypes[file_type]):
        extension_path = download_path + supported_filetypes[file_type]
    else:
        extension_path = download_path
    os.rename(download_path, extension_path)
    return extension_path

def report_already_downloaded(download_path):
    return bool(glob.glob(download_path) or glob.glob(f"{download_path}.*"))

# === Settings ===
download_all = False
num_reports = 80

# === Paths ===
base_dir = Path(__file__).resolve().parents[2]  # <-- this gets to project root
base_download_dir = base_dir / "data" / "pdf_reports"
base_download_dir.mkdir(parents=True, exist_ok=True)

sem = asyncio.Semaphore(10)

async def fetch_report_content(session, file_url, download_path, checksum):
    hash_check = hashlib.sha1()
    async with session.get(file_url) as response:
        if response.status != 200:
            print(f"[!] Failed to download {file_url} (status {response.status})")
            return
        try:
            with open(download_path, 'wb') as f:
                async for chunk in response.content.iter_chunked(1024):
                    if chunk:
                        hash_check.update(chunk)
                        f.write(chunk)
            if hash_check.hexdigest() != checksum:
                raise ValueError("File integrity check failed (SHA-1 mismatch)")
            final_path = verify_report_filetype(download_path)
            print(f"[+] Downloaded: {final_path}")
        except Exception as e:
            print(f"[!] Error saving {file_url}: {e}")
            if os.path.exists(download_path):
                try:
                    os.remove(download_path)
                except Exception as delete_err:
                    print(f"[!] Failed to delete bad file: {delete_err}")

async def fetch_report_url(session, report_link):
    async with session.get(report_link) as splash_response:
        if splash_response.status != 200:
            print(f"[!] Failed to fetch splash page: {report_link}")
            return None
        try:
            return get_download_url(await splash_response.read())
        except Exception as e:
            print(f"[!] Failed to extract file URL: {e}")
            return None

async def download_report(session, report):
    report_filename = report['Filename']
    report_year = report['Year']
    report_link = report['Link']
    report_sha1 = report['SHA-1']

    year_folder = base_download_dir / report_year
    year_folder.mkdir(parents=True, exist_ok=True)

    download_path = year_folder / report_filename

    if report_already_downloaded(str(download_path)):
        print(f"[=] Already exists: {report_filename}")
        return

    async with sem:
        file_url = await fetch_report_url(session, report_link)
        if file_url:
            await fetch_report_content(session, file_url, str(download_path), report_sha1)

async def download_all_reports(APT_reports):
    async with aiohttp.ClientSession() as session:
        selected_reports = APT_reports if download_all else APT_reports[:num_reports]
        tasks = [download_report(session, report) for report in selected_reports]
        await asyncio.gather(*tasks)

if __name__ == "__main__":
    if platform.system() == "Windows":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    all_reports = load_notes()
    asyncio.run(download_all_reports(all_reports))
