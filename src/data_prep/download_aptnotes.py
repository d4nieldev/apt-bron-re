# external
import magic
import aiohttp
from tqdm import tqdm
from bs4 import BeautifulSoup
import ssl

# built-in
import os
import json
import glob
import requests
import hashlib
import asyncio
import logging as log
from dataclasses import dataclass


APTNOTES_URL = 'https://raw.githubusercontent.com/aptnotes/data/master/APTnotes.json'
PDF_REPORTS_DIR = os.path.join('reports', 'pdf')
ssl_context = ssl._create_unverified_context()


@dataclass
class ReportData:
    Filename: str
    Title: str
    Source: str
    Link: str
    SHA1: str
    Date: str
    Year: str


def load_aptnotes() -> list[ReportData]:
    """
    Retrieve APT Note Data

    """
    github_url = APTNOTES_URL
    aptnotes_json = requests.get(github_url)

    if aptnotes_json.status_code == 200:
        # Load APT report metadata into JSON container
        apt_reports_data = json.loads(aptnotes_json.text)
    else:
        apt_reports_data = []
    
    # Reverse order of reports in order to download newest to oldest
    apt_reports_data.reverse()

    rename_map = { "SHA-1": "SHA1" }
    return [ReportData(**{rename_map.get(k, k): v for k, v in report_data.items()}) for report_data in apt_reports_data]


def get_download_url(page: bytes) -> str:
    """
    Parse preview page for desired elements to build download URL

    """
    soup = BeautifulSoup(page, 'lxml')
    scripts = soup.find('body').find_all('script')  # type: ignore
    sections = scripts[-1].contents[0].split(';')   # type: ignore
    app_api = json.loads(sections[0].split('=')[1])['/app-api/enduserapp/shared-item']

    # Build download URL
    box_url = "https://app.box.com/index.php"
    box_args = "?rm=box_download_shared_file&shared_name={}&file_id={}"
    file_url = box_url + box_args.format(app_api['sharedName'], 'f_{}'.format(app_api['itemID']))

    return file_url


def report_already_downloaded(download_path: str) -> bool:
    """
    Check if report is already downloaded

    """
    return len(glob.glob(download_path)) + len(glob.glob("{}.*".format(download_path))) > 0


def verify_report_filetype(download_path: str) -> str:
    """
    Identify filetype and add extension

    """
    supported_filetypes = { 
        "application/pdf": ".pdf",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx"
    }
    file_type = magic.from_file(download_path, mime=True)

    # Add supported extension to path
    if file_type in supported_filetypes and not download_path.endswith(supported_filetypes[file_type]):
        extension_path = download_path + supported_filetypes[file_type]

    # Leave as original download path
    else:
        extension_path = download_path

    os.rename(download_path, extension_path)
    download_path = extension_path

    return download_path


async def download_report(
        session: aiohttp.ClientSession, 
        report: ReportData, 
        sem: asyncio.Semaphore, 
        progress_bar: tqdm
    ):

    report_year = report.Year
    report_link = report.Link
    report_filename = report.Filename
    report_sha1 = report.SHA1

    # Set hash check
    hash_check = hashlib.sha1()

    # Set download path
    download_dir = os.path.join(PDF_REPORTS_DIR, report_year)
    download_path = os.path.join(PDF_REPORTS_DIR, report_year, report_filename)

    # Ensure directory exists
    os.makedirs(download_dir, exist_ok=True)

    if report_already_downloaded(download_path):
        log.info("[!] File {} already exists".format(report_filename))
    else:
        try:
            # Download report preview page for parsing
            async with session.get(report_link) as splash_response:
                splash_page = await splash_response.content.read()

            file_url = get_download_url(splash_page)

            # Use semaphore to limit download rate
            async with sem:
                # Download file in chunks and save to folder location
                async with session.get(file_url) as download_response:
                    with open(download_path, 'wb') as f_handle:
                        while True:
                            chunk = await download_response.content.read(1024)
                            hash_check.update(chunk)
                            if not chunk:
                                break
                            f_handle.write(chunk)
                    await download_response.release()

            # Verify file contents based on expected hash value
            if hash_check.hexdigest() != report_sha1:
                os.remove(download_path)
                raise ValueError("File integrity check failed")

            # Verify report filetype and add extension
            download_path = verify_report_filetype(download_path)
            log.info("[+] Successfully downloaded {}".format(download_path))
            progress_bar.update(1)
        except Exception as unexpected_error:
            message = "[!] Download failure for {}".format(report.Filename)
            log.warning(message, unexpected_error)


async def download_all_reports(
        APT_reports: list[ReportData],
        loop: asyncio.AbstractEventLoop,
        sem: asyncio.Semaphore
    ):
    progress_bar = tqdm(total=len(APT_reports), desc="Downloading Reports")
    async with aiohttp.ClientSession(loop=loop, connector=aiohttp.TCPConnector(ssl=ssl_context)) as session:
        download_queue = [loop.create_task(download_report(session, report, sem, progress_bar)) for report in APT_reports]
        await asyncio.wait(download_queue)


if __name__ == '__main__':
    # Retrieve APTNotes data
    aptnotes = load_aptnotes()

    # Set semaphore for rate limiting
    sem = asyncio.Semaphore(10)

    # Create async loop
    loop = asyncio.get_event_loop()
    loop.run_until_complete(download_all_reports(aptnotes, loop, sem))

