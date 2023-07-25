import os
import re

from assemblyline.odm.base import IP_ONLY_REGEX
from assemblyline_v4_service.common.api import ServiceAPIError
from assemblyline_v4_service.common.base import ServiceBase, ServiceRequest
from assemblyline_v4_service.common.result import (
    Result,
    ResultKeyValueSection,
    ResultTableSection,
    ResultImageSection,
    TableRow,
    Heuristic,
    ResultSection,
)
from hashlib import md5
from requests import Session
from tempfile import NamedTemporaryFile
from time import sleep
from datetime import datetime
from base64 import b64encode
from urllib.parse import urlparse


def format_domain_resolution(ip_loc: dict):
    ip = ip_loc.pop("ip")
    location = {"IP": ip}
    location.update(ip_loc)
    return location


class BeaverSessionClient(Session):
    def __init__(self, url_base, rate_limit) -> None:
        super().__init__()
        self.url_base = url_base + "/auth/api"
        self.rate_limit = rate_limit
        self.last_request = datetime.now()

    def request(self, method, url, **kwargs):
        url = self.url_base + url
        while (datetime.now() - self.last_request).seconds < self.rate_limit:
            # Wait until we're allowed to make another request
            sleep(max(abs(self.rate_limit - (datetime.now() - self.last_request).seconds), 1))
        self.last_request = datetime.now()
        return super().request(method, url, **kwargs)


class Beaver(ServiceBase):
    def __init__(self, config=None):
        # Initialize session with Beaver instance
        super(Beaver, self).__init__(config)
        self.session = BeaverSessionClient(self.config.get("base_url"), self.config.get("rate_limit"))
        self.session.headers = self.config.get("headers", {})
        self.safelist_regex = None
        self.safelist_match = []
        # Instantiate safelist(s)
        try:
            safelist = self.get_api_interface().get_safelist(
                [
                    "network.static.uri",
                    "network.dynamic.uri",
                    "network.static.domain",
                    "network.dynamic.domain",
                    "network.static.ip",
                    "network.dynamic.ip",
                ]
            )
            regex_list = []

            # Extend with safelisted matches
            [self.safelist_match.extend(match_list) for _, match_list in safelist.get("match", {}).items()]

            # Extend with safelisted regex
            [regex_list.extend(regex_) for _, regex_ in safelist.get("regex", {}).items()]

            self.safelist_regex = re.compile("|".join(regex_list))

        except ServiceAPIError as e:
            self.log.warning(f"Couldn't retrieve safelist from service server: {e}. Continuing without it..")

    def start(self):
        # Check to see if we can actually get a response
        resp = self.session.get("/statsJson")
        if not resp.ok:
            raise Exception(f"Unsuccessful connection to {resp.request.url}: {resp.reason}")

    def parse_file_report(self, report: dict, sha256: str) -> ResultSection:
        result = ResultSection(sha256)
        malware_report = report.get("malwareReport", {})

        callout_section = ResultTableSection("Sandbox Call-Outs", heuristic=Heuristic(4))
        ip_loc = ResultTableSection("IP Location Details", parent=callout_section)
        av_section = ResultTableSection("Anti-Virus Detections")
        for reports in malware_report.get("reports", {}).values():
            for report in reports:
                if report.get("results"):
                    # Antivirus Scans
                    engine_name = report["analysisType"]
                    for av_name, av_result in report["results"].items():
                        if av_result.get("result"):
                            ResultKeyValueSection(
                                f"{engine_name}: {av_name} identified file as {av_result['result']}",
                                body=av_result,
                                parent=av_section,
                                auto_collapse=True,
                                heuristic=Heuristic(3),
                                tags={"av.virus_name": [f"{av_name}.{av_result['result']}"]},
                            )

        for reports in malware_report.get("dbCNCMap", {}).values():
            for report in reports:
                if report.get("callout"):
                    callout = report["callout"]
                    path = callout["channel"]
                    domain = callout["domain"] if callout["domain"] != callout["ip"] else None
                    if " /" in path:
                        path = path.split(" ", 2)[1]
                    callout_section.add_row(
                        TableRow(
                            {
                                "Protocols": [p.upper() for p in callout["protocols"]],
                                "Host": f"{callout['ip']} ({domain})" if domain else callout["ip"],
                                "Port": callout["port"],
                                "Path": path if len(path) < 255 else f"{path[:255]} ...",
                            }
                        )
                    )
                    if domain:
                        callout_section.add_tag("network.dynamic.domain", domain)
                    callout_section.add_tag("network.dynamic.ip", callout["ip"])
                    callout_section.add_tag("network.port", callout["port"])

                for domain in report.get("domains", []):
                    ip_loc.add_tag("network.dynamic.ip", domain["ipLocation"]["ip"])
                    row = TableRow(format_domain_resolution(domain["ipLocation"]))
                    if row not in ip_loc.section_body._data:
                        ip_loc.add_row(row)

        if av_section.subsections:
            av_section.title_text += f" (x{len(av_section.subsections)})"
            result.add_subsection(av_section)
        if callout_section.body:
            # Format table
            callout_section.title_text += f" (x{len(callout_section.section_body._data)})"
            callout_section.section_body._data = sorted(callout_section.section_body._data, key=lambda x: x["Host"])
            ip_loc.section_body._data = sorted(ip_loc.section_body._data, key=lambda x: x["IP"])
            result.add_subsection(callout_section)
        return result

    def parse_domain_ip_report(self, report: dict, subject: str, type: str) -> ResultSection:
        result = ResultSection(subject)

        # DFS
        if "DFS" in report["allowedSystems"]:
            resp = self.session.get(f"/{type}/{subject}/report/fetch/DFS")
            if resp.ok:
                dfs_report = resp.json()
                domain_res = ResultTableSection("Domain Resolution(s)")
                for r in dfs_report.get("reports", []):
                    if r["type"] == "PassiveDNS":
                        for d in r["data"]:
                            d.pop("sourceName")
                            d.pop("sourceId")
                            d["addedOn"] = sorted(d["addedOn"])[-1]
                            domain_res.add_tag("network.static.ip", d["ip"])
                            domain_res.add_tag("network.static.domain", d["domain"])
                            if len(domain_res.section_body._data) <= 10:
                                domain_res.add_row(TableRow(format_domain_resolution(d)))
                            else:
                                pass

                if domain_res.section_body._data:
                    result.add_subsection(domain_res)

        # MOOSE
        if "MOOSE" in report["allowedSystems"]:
            resp = self.session.get(f"/{type}/{subject}/report/fetch/MOOSE")
            if resp.ok:
                moose_report = resp.json()
                families, infra = [], []
                for r in moose_report.get("reports", []):
                    if r["type"] == "CTI":
                        for s in r["summaries"]:
                            if s["title"] == "Families":
                                families.extend(s.get("list", []) or [])
                            elif s["title"] == "Infrastructures":
                                infra.extend(s.get("list", []) or [])
                moose_section = ResultKeyValueSection("MOOSE Analysis")
                if families:
                    moose_section.set_item("Family", families)
                    [moose_section.add_tag("attribution.family", f) for f in families]
                if infra:
                    moose_section.set_item("Infrastructures", infra)
                if moose_section.body:
                    result.add_subsection(moose_section)
        return result

    def parse_url_report(self, report: dict, url: str, request: ServiceRequest) -> ResultSection:
        result = ResultSection(url)

        # Network Activity / Communications
        def append_to_communication_table(comm: dict, table: list, depth=0):
            if comm["entry"]:
                table.append(
                    {
                        "Status Code": comm["entry"]["response"]["statusCode"],
                        "Request": "↳" * depth
                        + " "
                        + f"{comm['entry']['request']['method']} {comm['entry']['request']['url']}",
                        "MIME Type": comm["entry"]["response"]["content"]["mimeType"].split(";")[0],
                        "url": comm["entry"]["request"]["url"],
                    }
                )
            for c in comm["children"]:
                append_to_communication_table(c, table, depth + 1)

        comms_list = []
        for c in report.get("communications", []):
            append_to_communication_table(c, comms_list)

        if comms_list:
            comms_table = ResultTableSection(title_text="Network Activity Upon Visit", parent=result)
            for c in comms_list:
                uri = c.pop("url")
                hostname = urlparse(uri).hostname
                if re.match(IP_ONLY_REGEX, hostname):
                    comms_table.add_tag("network.dynamic.ip", hostname)
                else:
                    comms_table.add_tag("network.dynamic.domain", hostname)
                comms_table.add_tag("network.dynamic.uri", uri)
                comms_table.add_row(TableRow(c))

        # Domain Resolutions
        if report["report"].get("domainResolutions"):
            domain_res = ResultTableSection(title_text="Domain Resolution(s)", parent=result)
            for resolution in report["report"]["domainResolutions"]:
                ip_location = resolution["ipLocation"]
                if ip_location.get("domain"):
                    domain_res.add_tag("network.static.domain", ip_location["domain"])
                domain_res.add_tag("network.static.ip", ip_location["ip"])
                domain_res.add_row(TableRow(format_domain_resolution(ip_location)))

        # TODO: Have a way to tell if screenshots contain illicit content before displaying
        # # Screenshots
        # if report.get("screenshotLinks"):
        #     b64_md5_url = b64encode(md5(url.encode()).hexdigest().encode()).decode()
        #     screenshot_section = ResultImageSection(request, "Screenshots", parent=result)
        #     for ss_link in report["screenshotLinks"]:
        #         resp = self.session.get(f"{ss_link}/{b64_md5_url}")
        #         if resp.ok:
        #             fh = NamedTemporaryFile("wb", delete=False, dir=self.working_directory)
        #             fh.write(resp.content)
        #             fh.close()
        #             screenshot_section.add_image(fh.name, os.path.basename(ss_link), f"Screenshot from {url}")
        return result

    def execute(self, request):
        request.result = Result()
        resp = self.session.get(f"/sha256/{request.sha256}/json")
        if resp.ok:
            # File exists in Beaver, parse response
            self.log.info(f"Found {request.sha256} in Beaver database")
            request.result.add_section(self.parse_file_report(resp.json(), request.sha256))

        task_tags = request.task.tags
        domains = list(set(task_tags.get("network.static.domain", []) + task_tags.get("network.dynamic.domain", [])))
        urls = list(set(task_tags.get("network.static.uri", []) + task_tags.get("network.dynamic.uri", [])))
        ips = list(set(task_tags.get("network.static.ip", []) + task_tags.get("network.dynamic.ip", [])))

        domains = ["canada.ca", "dpbqyqxynbip.ru"]
        urls = ["https://qazaqtravel.kz/admin/login.php"]
        ips = ["50.63.110.1"]

        if urls:
            url_section = ResultSection("Extracted URLs from Assemblyline", auto_collapse=True)
            for url in urls:
                resp = self.session.get(f"/url/{md5(url.encode()).hexdigest()}/json")
                if resp.ok:
                    url_section.add_subsection(self.parse_url_report(resp.json(), url, request))
            if url_section.subsections:
                request.result.add_section(url_section)

        if domains:
            domain_section = ResultSection("Extracted Domains from Assemblyline", auto_collapse=True)
            for domain in domains:
                resp = self.session.get(f"/domain/{domain}/json")
                if resp.ok:
                    domain_section.add_subsection(self.parse_domain_ip_report(resp.json(), domain, "domain"))
            if domain_section.subsections:
                request.result.add_section(domain_section)

        if ips:
            ip_section = ResultSection("Extracted IPs from Assemblyline", auto_collapse=True)
            for ip in ips:
                resp = self.session.get(f"/ip/{ip}/json")
                if resp.ok:
                    ip_section.add_subsection(self.parse_domain_ip_report(resp.json(), ip, "ip"))
            if ip_section.subsections:
                request.result.add_section(ip_section)

        return
