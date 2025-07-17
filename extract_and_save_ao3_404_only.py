import re
import requests
from io import BytesIO
from PyPDF2 import PdfReader
from bs4 import BeautifulSoup
import time
import getpass
import urllib.parse
import os
import tempfile
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, asdict
from contextlib import contextmanager

# OCR Imports (optional, but recommended for scanned PDFs)
try:
    import pytesseract
    from pdf2image import convert_from_path
    OCR_ENABLED = True
except ImportError:
    OCR_ENABLED = False

# --- Configuration ---
@dataclass
class Config:
    """Configuration settings for the scraper."""
    input_file: str = "urls.txt"
    output_html_file: str = "404_works_report.html"
    log_file: str = "404_scraper.log"
    master_data_file: str = "master_404_data.json"
    known_ok_file: str = "known_ok_urls.txt"
    # --- RATE LIMIT SETTINGS ---
    base_request_delay: float = 2.0
    request_timeout: int = 60
    max_retries: int = 5
    retry_delay: float = 10.0

config = Config()

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(config.log_file),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

if not OCR_ENABLED:
    logger.warning("pytesseract or pdf2image not found. OCR capabilities will be disabled.")
    logger.warning("To enable OCR, run: pip install pytesseract pdf2image")

# --- Data Structures ---
@dataclass
class WorkResult:
    """Represents the data extracted for a single work."""
    url: str
    title: str
    summary: str
    stats: Optional[Dict[str, str]]
    not_found: bool = True
    pdf_url: Optional[str] = None

class AO3NotFoundScraper:
    """
    A single-threaded, accurate scraper to find AO3 works that are 'Not Found' (404)
    by checking links within a list of PDF files.
    """
    def __init__(self):
        self.pattern = re.compile(r"https?://\s*archiveofourown\.org\s*/\s*works\s*/\s*(\d+)")
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept-Language": "en-US,en;q=0.9",
        }
        self.session = requests.Session()
        self.session.headers.update(self.headers)

        self.session_results: List[WorkResult] = []
        self.processed_work_urls: Set[str] = set()

        self.master_data: Dict[str, WorkResult] = self._load_master_data()
        self.known_404_urls: Set[str] = set(self.master_data.keys())
        self.known_ok_urls: Set[str] = self._load_known_ok_urls()

    def _load_master_data(self) -> Dict[str, WorkResult]:
        """Loads the master data file containing all previously found 404 works."""
        if not os.path.exists(config.master_data_file):
            return {}
        try:
            with open(config.master_data_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                master_results = {url: WorkResult(**res_dict) for url, res_dict in data.items()}
                logger.info(f"Loaded {len(master_results)} records from {config.master_data_file}.")
                return master_results
        except (json.JSONDecodeError, TypeError) as e:
            logger.error(f"Could not read or parse master data file '{config.master_data_file}': {e}")
            return {}

    def _save_master_data(self):
        """Saves the master data to the persistent JSON file."""
        logger.info(f"Saving {len(self.master_data)} total records to {config.master_data_file}.")
        try:
            with open(config.master_data_file, "w", encoding="utf-8") as f:
                serializable_data = {url: asdict(res) for url, res in self.master_data.items()}
                json.dump(serializable_data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"Failed to save master data to JSON: {e}")

    def _load_known_ok_urls(self) -> Set[str]:
        """Loads previously found working (OK) URLs from the persistent file."""
        if not os.path.exists(config.known_ok_file):
            return set()
        try:
            with open(config.known_ok_file, "r", encoding="utf-8") as f:
                urls = {line.strip() for line in f if line.strip()}
                logger.info(f"Loaded {len(urls)} known OK URLs from {config.known_ok_file}.")
                return urls
        except Exception as e:
            logger.error(f"Could not read known OK URLs file: {e}")
            return set()

    def _save_ok_url(self, work_url: str):
        """Appends a newly found working (OK) URL to the persistent file."""
        try:
            with open(config.known_ok_file, "a", encoding="utf-8") as f:
                f.write(work_url + "\n")
            self.known_ok_urls.add(work_url)
        except Exception as e:
            logger.error(f"Failed to save new OK URL {work_url}: {e}")

    def login_to_ao3(self, username: str, password: str) -> bool:
        """Logs into AO3 using the main session."""
        if not username or not password:
            logger.error("Username and password are required for accurate checking.")
            return False

        login_url = "https://archiveofourown.org/users/login"
        try:
            logger.info("Attempting to login to AO3...")
            login_page = self.session.get(login_url, timeout=config.request_timeout)
            login_page.raise_for_status()
            soup = BeautifulSoup(login_page.text, "html.parser")
            token_input = soup.find("input", {"name": "authenticity_token"})
            if not token_input:
                logger.error("Could not find authenticity_token on login page.")
                return False

            payload = {
                "user[login]": username,
                "user[password]": password,
                "authenticity_token": token_input["value"],
                "commit": "Log in"
            }
            response = self.session.post(login_url, data=payload, timeout=config.request_timeout)
            response.raise_for_status()

            if "Log Out" in response.text or "My Dashboard" in response.text:
                logger.info("Successfully logged into AO3. Session cookies are set.")
                return True
            else:
                logger.error("Login failed. Please check your credentials.")
                return False
        except requests.exceptions.RequestException as e:
            logger.error(f"A network error occurred during login: {e}")
            return False
        except Exception as e:
            logger.error(f"An unexpected error occurred during login: {e}")
            return False

    def check_work_status(self, work_url: str) -> str:
        """
        Accurately checks the status of a work URL.
        Returns '404', 'OK', or 'ERROR'.
        """
        work_url = work_url.replace("http://", "https://")

        for attempt in range(config.max_retries):
            time.sleep(config.base_request_delay)
            logger.info(f"Checking status of {work_url} (Attempt {attempt + 1}/{config.max_retries})")
            try:
                response = self.session.get(work_url, timeout=config.request_timeout)
                logger.info(f"URL: {work_url} | Status: {response.status_code}")

                if response.status_code == 429:
                    retry_after = int(response.headers.get("Retry-After", 60))
                    logger.warning(f"Rate limit hit (429). Waiting for {retry_after}s.")
                    print(f"\nRate limit hit. Waiting for {retry_after} seconds...")
                    time.sleep(retry_after)
                    continue

                if response.status_code == 404:
                    logger.warning(f"CONFIRMED 404: Work not found at {work_url}")
                    return "404"

                response.raise_for_status()

                soup = BeautifulSoup(response.text, 'html.parser')
                title_heading = soup.select_one("h2.title.heading")

                if title_heading:
                    logger.info(f"Work is available (200 OK and content verified): {work_url}")
                    return "OK"
                else:
                    logger.warning(f"URL {work_url} returned OK but content is not a work. Assuming restricted/private.")
                    return "OK"

            except requests.exceptions.RequestException as e:
                logger.warning(f"Request failed for {work_url}: {e}")
                if attempt < config.max_retries - 1:
                    delay = config.retry_delay * (attempt + 1)
                    logger.info(f"Waiting for {delay:.2f} seconds before retrying.")
                    time.sleep(delay)
                else:
                    logger.error(f"Final attempt failed for {work_url}.")

        logger.error(f"Failed to get a valid response from {work_url} after all attempts.")
        return "ERROR"

    @contextmanager
    def _temporary_pdf_file(self, content: bytes):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp_file:
            tmp_file.write(content)
            tmp_path = tmp_file.name
        try: yield tmp_path
        finally:
            try: os.remove(tmp_path)
            except OSError: pass

    def _extract_text_from_pdf(self, pdf_path: str) -> str:
        text = ""
        try:
            with open(pdf_path, "rb") as f:
                reader = PdfReader(f)
                for page in reader.pages:
                    extracted = page.extract_text()
                    if extracted: text += extracted + "\n"
        except Exception as e:
            logger.warning(f"PyPDF2 failed on {os.path.basename(pdf_path)}: {e}. OCR might be needed.")

        if OCR_ENABLED and len(text.strip()) < 200:
            logger.info(f"Minimal text found. Attempting OCR...")
            try:
                images = convert_from_path(pdf_path, first_page=1, last_page=5)
                ocr_text_parts = [pytesseract.image_to_string(image) for image in images]
                text = text + "\n" + "\n".join(ocr_text_parts)
                logger.info("Successfully extracted text with OCR.")
            except Exception as ocr_error:
                logger.error(f"OCR processing failed: {ocr_error}")
        return text.strip()
    
    def _extract_summary_from_pdf_text(self, text: str) -> str:
        """Extracts the summary and cleans it of known unwanted sentences."""
        summary_start_match = re.search(r'Summary\s*[:\n]', text, re.IGNORECASE)
        if not summary_start_match:
            return "No summary found"

        text_after_summary = text[summary_start_match.end():]

        summary_end_pattern = re.compile(
            r'Chapter \d+|Chapter Notes|Notes:|Author:|Title:|Rating:|Fandom:|Pairing:|Characters?:',
            re.IGNORECASE
        )
        summary_end_match = summary_end_pattern.search(text_after_summary)

        raw_block = text_after_summary[:summary_end_match.start()] if summary_end_match else text_after_summary
        summary = raw_block.strip()

        while True:
            lines = summary.splitlines()
            if not lines: break
            last_line = lines[-1].strip()
            is_likely_title = (len(last_line.split()) < 10 and len(last_line) < 70 and last_line and not last_line.endswith(('.', '!', '?', '"', "'", '”', ')')))
            if is_likely_title:
                summary = '\n'.join(lines[:-1]).strip()
            else:
                break

        unwanted_sentence_text = "Please drop by the archive and comment to let the author know if you enjoyed their work!"
        words = [re.escape(word) for word in unwanted_sentence_text.split()]
        unwanted_pattern = r'\s+'.join(words)

        summary = re.sub(unwanted_pattern, '', summary, flags=re.IGNORECASE).strip()

        return re.sub(r'\s+', ' ', summary).strip()

    def extract_metadata_from_pdf_text(self, text: str) -> Tuple[str, str, Dict[str, str]]:
        """
        Parses the text of a PDF to extract fanfic metadata.
        """
        lines = [line.strip() for line in text.strip().splitlines() if line.strip()]
        if not lines: return "Unknown Title", "No content found", {}
        
        header_end_index = len(lines) 
        metadata_start_pattern = re.compile(r'^(Rating|Archive Warning|Category|Fandom|Relationship|Character|Additional Tags|Language|Series|Collections|Stats):', re.IGNORECASE)
        for i, line in enumerate(lines):
            if metadata_start_pattern.search(line):
                header_end_index = i
                break
        
        candidate_title_block = ' '.join(lines[:header_end_index]).strip()
        
        posted_phrase_pattern = re.compile(r'Posted\s+originally\s+on\s+the\s+Archive\s+of\s+Our\s+Own', re.IGNORECASE)
        match = posted_phrase_pattern.search(candidate_title_block)
        if match:
            title = candidate_title_block[:match.start()].strip()
        else:
            title = candidate_title_block

        if not title:
             title = "Unknown Title"

        summary = self._extract_summary_from_pdf_text(text)
        metadata = {}

        metadata_patterns = {
            "Rating": r"Rating:\s*(.+?)(?=\n\s*(?:Archive Warning:|Category:)|$)",
            "Archive Warning": r"Archive Warning:\s*(.+?)(?=\n\s*(?:Category:|Fandom:)|$)",
            "Category": r"Category:\s*(.+?)(?=\n\s*(?:Fandom:|Relationship:)|$)",
            "Fandom": r"Fandom:\s*(.+?)(?=\n\s*(?:Relationship:|Character:)|$)",
            "Relationship": r"Relationship:\s*(.+?)(?=\n\s*(?:Character:|Additional Tags:)|$)",
            "Character": r"Character:\s*(.+?)(?=\n\s*(?:Additional Tags:|Language:)|$)",
            "Additional Tags": r"Additional Tags:\s*(.+?)(?=\n\s*(?:Series:|Collections:|Language:|Stats:|Published:)|$)",
            "Series": r"Series:\s*(.+?)(?=\n\s*(?:Collections:|Stats:|Published:)|$)",
            "Collections": r"Collections:\s*(.+?)(?=\n\s*(?:Stats:|Published:)|$)",
            "Language": r"Language:\s*(.+?)(?=\n\s*(?:Stats:|Published:|Words:)|$)",
            "Published": r"Published:\s*([\d-]+)",
            "Updated": r"Updated:\s*([\d-]+)",
            "Words": r"Words:\s*([\d,]+)",
            "Chapters": r"Chapters:\s*([\d/]+)",
        }

        text_head = "\n".join(lines[:150])

        for key, pattern in metadata_patterns.items():
            match = re.search(pattern, text_head, re.DOTALL | re.IGNORECASE)
            if match:
                value = match.group(1).strip()
                value = re.sub(r'\s*\n\s*', ' ', value)
                value = re.sub(r'\s*,\s*', ', ', value)
                normalized_value = re.sub(r'\s+', ' ', value).strip()
                metadata[key] = normalized_value

        stats_match = re.search(r"Stats:\s*(.+)", text_head, re.IGNORECASE)
        if stats_match:
            stats_line = stats_match.group(1)
            stats_pairs = re.findall(r"(Published|Updated|Words|Chapters):\s*([\d,/-]+)", stats_line)
            for key, value in stats_pairs:
                if key not in metadata:
                    metadata[key] = value.strip()

        return title.strip(), summary, metadata

    def process_all_pdfs(self, pdf_urls: List[str]):
        """
        Processes all PDFs sequentially to find 404 works.
        """
        total_urls = len(pdf_urls)
        for i, pdf_url in enumerate(pdf_urls):
            print(f"Processing PDF {i+1}/{total_urls}: {os.path.basename(pdf_url)}", end='\r')

            try:
                time.sleep(config.base_request_delay / 2)
                response = self.session.get(pdf_url, timeout=config.request_timeout)
                response.raise_for_status()

                if not response.content or len(response.content) < 1024:
                    logger.error(f"File from {pdf_url} is empty. Skipping.")
                    continue

                with self._temporary_pdf_file(response.content) as tmp_path:
                    pdf_text_content = self._extract_text_from_pdf(tmp_path)
                    found_work_ids = set(self.pattern.findall(pdf_text_content))

                if not found_work_ids:
                    logger.warning(f"No AO3 link found in PDF: {pdf_url}.")
                    continue

                for work_id in found_work_ids:
                    work_url = f"https://archiveofourown.org/works/{work_id}"

                    if work_url in self.processed_work_urls:
                        logger.info(f"Skipping already checked URL in this session: {work_url}")
                        continue

                    if work_url in self.known_404_urls:
                        logger.info(f"Skipping known 404 URL from previous runs: {work_url}")
                        continue
                    
                    if work_url in self.known_ok_urls:
                        logger.info(f"Skipping known OK URL from previous runs: {work_url}")
                        continue

                    status = self.check_work_status(work_url)
                    self.processed_work_urls.add(work_url)

                    if status == "404":
                        print(f"\n[FOUND 404] {work_url}")
                        logger.info(f"✅ FOUND 404: {work_url}. Extracting metadata.")
                        title, summary, meta = self.extract_metadata_from_pdf_text(pdf_text_content)

                        result = WorkResult(
                            url=work_url, title=title or os.path.basename(pdf_url),
                            summary=summary, stats=meta, pdf_url=pdf_url
                        )
                        self.session_results.append(result)
                        self.master_data[work_url] = result
                    
                    elif status == "OK":
                        logger.info(f"Found working URL: {work_url}. Adding to known OK list.")
                        self._save_ok_url(work_url)

            except Exception as e:
                logger.error(f"A critical error occurred while processing {pdf_url}: {e}", exc_info=True)


    def generate_report(self, results_to_report: List[WorkResult], report_title: str):
        """Generates the HTML report from a given list of results."""
        if not results_to_report:
            logger.warning("No results to report, skipping HTML report generation.")
            print("\nNo works to include in the report.")
            return

        logger.info(f"Generating HTML report for {len(results_to_report)} works...")
        work_entries_html = ""
        for work in sorted(results_to_report, key=lambda x: x.title):
            stats_html = '<div class="stats">'
            if work.stats:
                stat_order = ["Rating", "Archive Warning", "Category", "Fandom", "Relationship", "Character",
                              "Additional Tags", "Series", "Collections", "Language", "Published", "Updated",
                              "Words", "Chapters"]

                display_stats = {k: work.stats[k] for k in stat_order if k in work.stats}
                display_stats.update({k: v for k, v in work.stats.items() if k not in display_stats})

                for k, v in display_stats.items():
                    stats_html += f'<div class="stat-item"><strong>{self._escape_html(k)}:</strong> {self._escape_html(v)}</div>'
            stats_html += '</div>'

            work_entries_html += f"""
            <div class="work-entry">
                <h2 class="title"><a href="{work.pdf_url}" target="_blank">{self._escape_html(work.title)}</a></h2>
                <div class="summary">{self._escape_html(work.summary)}</div>
                {stats_html}
            </div>"""

        css_content = "body{font-family:'Times New Roman',Times,serif;margin:0;background-color:#fff;color:#333;line-height:1.6;}.container{max-width:900px;margin:2rem auto;padding:1rem 2rem;background-color:#fff;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,0.1);}h1{text-align:center;color:#5B92E5;border-bottom:2px solid #cce0ff;padding-bottom:1rem;margin-bottom:2rem;}.work-entry{border:1px solid #cce0ff;border-radius:8px;margin-bottom:1.5rem;padding:1.5rem;}.title{font-size:1.5rem;margin-top:0;margin-bottom:.5rem;color:#004a99;}.title a{color:inherit;text-decoration:none;}.title a:hover{text-decoration:underline;}.summary{margin-top:1rem;padding-top:1rem;border-top:1px solid #eaf4ff;color:#333;}.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:.5rem 1rem;margin-top:1rem;font-size:.9rem;}.stat-item{background-color:#eaf4ff;padding:.4rem .8rem;border-radius:4px;}.stat-item strong{color:#004a99;}"
        html_content = f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Report of 'Not Found' AO3 Works</title><style>{css_content}</style></head><body><div class="container"><h1>{report_title}</h1>{work_entries_html}</div></body></html>"""

        try:
            with open(config.output_html_file, "w", encoding="utf-8") as f:
                f.write(html_content)
            print(f"\n✅ Success! Report generated: {config.output_html_file}")
        except Exception as e:
            logger.error(f"Failed to generate HTML report: {e}")

    def _escape_html(self, text: str) -> str:
        if not text: return ""
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#x27;")
    
    def fresh_parse_all_known_404s(self):
        """Re-downloads and re-parses metadata for all known 404 works."""
        print("--- Refreshing Metadata for All Known 404s ---")
        if not self.master_data:
            print("\nMaster data file is empty. Run a (S)crape first.")
            return

        total_works = len(self.master_data)
        logger.info(f"Starting fresh parse for {total_works} works.")
        print(f"This will re-download {total_works} PDFs to refresh metadata. This may take a while.")
        
        updated_master_data = self.master_data.copy()

        for i, (work_url, work_result) in enumerate(updated_master_data.items()):
            pdf_url = work_result.pdf_url
            if not pdf_url:
                logger.warning(f"Skipping {work_url} because it has no associated PDF URL.")
                continue

            print(f"Processing {i+1}/{total_works}: {os.path.basename(pdf_url)}", end='\r')
            
            try:
                time.sleep(config.base_request_delay / 2)
                response = self.session.get(pdf_url, timeout=config.request_timeout)
                response.raise_for_status()

                if not response.content or len(response.content) < 1024:
                    logger.error(f"File from {pdf_url} is empty. Skipping refresh for {work_url}.")
                    continue

                with self._temporary_pdf_file(response.content) as tmp_path:
                    pdf_text_content = self._extract_text_from_pdf(tmp_path)
                
                title, summary, meta = self.extract_metadata_from_pdf_text(pdf_text_content)
                
                updated_result = WorkResult(
                    url=work_url,
                    title=title or os.path.basename(pdf_url),
                    summary=summary,
                    stats=meta,
                    pdf_url=pdf_url
                )
                updated_master_data[work_url] = updated_result

            except Exception as e:
                logger.error(f"Could not refresh {pdf_url} for work {work_url}: {e}", exc_info=True)
                print(f"\nFailed to refresh {os.path.basename(pdf_url)}. See log for details. Keeping old data.")
        
        print("\n\n--- Refresh Complete ---")
        self.master_data = updated_master_data
        self._save_master_data()
        
        report_title = f"Complete Report of 'Not Found' AO3 Works ({len(self.master_data)} Total)"
        self.generate_report(list(self.master_data.values()), report_title)

    def run(self):
        """Main execution flow, controlled by user input."""
        logger.info("--- AO3 'Not Found' Scraper ---")

        mode = ''
        while mode not in ['s', 'r', 'f']:
            mode = input("\nChoose operation:\n (S)crape for new 404s\n (R)egenerate full report\n (F)resh-parse all known 404s\n> ").lower().strip()

        if mode == 'r':
            print("--- Regenerating Full Report ---")
            all_results = list(self.master_data.values())
            report_title = f"Complete Report of 'Not Found' AO3 Works ({len(all_results)} Total)"
            self.generate_report(all_results, report_title)
            print(f"🔹 A detailed log is available at: {config.log_file}")
            return
            
        if mode == 'f':
            self.fresh_parse_all_known_404s()
            return

        # --- Scrape Mode ---
        print("--- Starting Scrape Mode ---")
        print("\n🔐 AO3 Login is required for accurate results.")
        username = input("AO3 Username: ").strip()
        if not username:
            print("Username cannot be empty. Exiting.")
            return
        password = getpass.getpass("AO3 Password: ")

        if not self.login_to_ao3(username, password):
            print("\n❌ Login failed. Please check your credentials and try again. Exiting.")
            return

        try:
            with open(config.input_file, "r") as f:
                urls = [line.strip() for line in f if line.strip() and line.startswith('http')]
        except FileNotFoundError:
            logger.error(f"Input file '{config.input_file}' not found.")
            print(f"\n❌ Error: Input file '{config.input_file}' not found.")
            return

        if not urls:
            logger.error(f"No URLs found in '{config.input_file}'.")
            print(f"\n❌ Error: No URLs found in '{config.input_file}'.")
            return

        logger.info(f"Found {len(urls)} PDF URLs to process.")
        print(f"\nProcessing {len(urls)} PDF URLs sequentially. This will take time...")

        self.process_all_pdfs(urls)

        print("\n\n--- Processing Complete ---")
        if self.session_results:
            self._save_master_data()

        # --- UPDATED: Always generate a full, cumulative report ---
        all_results = list(self.master_data.values())
        report_title = f"Complete Report of 'Not Found' AO3 Works ({len(all_results)} Total)"
        self.generate_report(all_results, report_title)

        if self.session_results:
            print(f"\nFound {len(self.session_results)} new works that were 'Not Found'.")
        else:
            print("\nNo new 'Not Found' works were identified in this session.")

        print(f"🔹 All {len(self.master_data)} unique 404 works are tracked in: {config.master_data_file}")
        print(f"🔹 All {len(self.known_ok_urls)} unique working URLs are tracked in: {config.known_ok_file}")
        print(f"🔹 A detailed log has been saved to: {config.log_file}")


if __name__ == "__main__":
    scraper = AO3NotFoundScraper()
    scraper.run()
