from lxml import html
from cpe import CPE
from dataclasses import dataclass
from typing import List, Any, Dict
import requests
IGNORED_CPES = {"cpe:/o:linux:linux_kernel"}


@dataclass
class NIDS:
    summary: str
    link: str
    score: str


class NDISHtml:

    def __init__(self):
        """
        Some CPE return too many false positives,
        so they are ignored right out the bat
        """
        self.raw_html = None
        self.parsed_results = []
        self.url = "https://nvd.nist.gov/vuln/search/results"
        self.ignored_cpes = IGNORED_CPES

    def get(self, cpe: str) -> str:
        """
        Run a CPE search on the NDIS website. If the CPE has no version then skip the search
        as it will return too many false positives
        @param cpe: CPE identifier coming from Nmap, like cpe:/a:openbsd:openssh:8.0
        @return:
        """
        params = {
            'form_type': 'Basic',
            'results_type': 'overview',
            'search_type': 'all',
            'isCpeNameSearch': 'false',
            'query': cpe
        }
        if cpe in self.ignored_cpes:
            return ""
        valid_cpe = CPE(cpe)
        if not valid_cpe.get_version()[0]:
            return ""
        response = requests.get(
            url=self.url,
            params=params
        )
        response.raise_for_status()
        return response.text

    def parse(self, html_data: str) -> list[NIDS]:
        """
        Parse NDIS web search. Not aware that they offer a REST API that doesn't require parsing.
        It is assumed that this method is never called directly by end users, so no further checks are done on the
        HTML file contents.
        @param html_data: RAW HTML used for scrapping
        @return: List of NDIS, if any
        """
        self.parsed_results = []
        if html_data:
            ndis_html = html.fromstring(html_data)
            # 1:1 match between 3 elements, use parallel array
            summary = ndis_html.xpath(
                "//*[contains(@data-testid, 'vuln-summary')]")
            cve = ndis_html.xpath(
                "//*[contains(@data-testid, 'vuln-detail-link')]")
            score = ndis_html.xpath(
                "//*[contains(@data-testid, 'vuln-cvss2-link')]")
            for i in range(len(summary)):
                ndis = NIDS(
                    summary=summary[i].text,
                    link="https://nvd.nist.gov/vuln/detail/" + cve[i].text,
                    score=score[i].text
                )
                self.parsed_results.append(ndis)
        return self.parsed_results

    def correlate_nmap_with_nids(self, parsed_xml: List[Dict[str, Any]]) -> Dict[str, List[NIDS]]:
        correlated_cpe = {}
        for row_data in parsed_xml:
            ports = row_data['ports']
            for port_data in ports:
                for cpe in port_data['cpes']:
                    raw_ndis = self.get(cpe)
                    cpes = self.parse(raw_ndis)
                    correlated_cpe[cpe] = cpes
        return correlated_cpe
