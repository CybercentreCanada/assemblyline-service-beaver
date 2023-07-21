import json

from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.result import Result, ResultKeyValueSection, ResultTableSection, TableRow
from requests import Session


class BeaverSessionClient(Session):
    def __init__(self, url_base) -> None:
        super().__init__()
        self.url_base = url_base

    def request(self, method, url, **kwargs):
        url = self.url_base + url
        return super().request(method, url, **kwargs)


class Beaver(ServiceBase):
    def __init__(self, config=None):
        # Initialize session with Beaver instance
        super(Beaver, self).__init__(config)
        self.session = BeaverSessionClient(self.config.get('base_url'))
        self.session.headers = self.config.get('headers', {})

    def start(self):
        # Check to see if we can actually get a response
        resp = self.session.get('/auth/api/statsJson')
        if not resp.ok:
            raise Exception(f'Unsuccessful connection to {resp.request.url}: {resp.reason}')

    def parse_json(report: dict) -> Result:
        result = Result()
        malware_report = report.get('malwareReport', {})

        callout_section = ResultTableSection('Sandbox Call-Outs')
        av_section = ResultTableSection('Anti-Virus Detections')
        for reports in malware_report.get('reports', {}).values():
            for report in reports:
                if report.get('networkReports'):
                    # Sandbox Callouts
                    engine_name = report['engineName']
                    for network_report in report['networkReports']:
                        if network_report.get('calloutStructure'):
                            for callout in network_report['calloutStructure'].get('callouts', []):
                                callout_section.add_row(TableRow(
                                    {
                                        'Engine': engine_name,
                                        'Version': report.get('engineVersion', 'UNKNOWN'),
                                        'IP': callout['ip'],
                                        'Port': callout['port'],
                                        'Path': callout['channel'].split(' ', 1)[-1]
                                    }
                                ))
                elif report.get('results'):
                    # Antivirus Scans
                    for av_name, result in report['results'].items():
                        if result.get('result'):
                            ResultKeyValueSection(f"{engine_name}: {av_name} identified file as {result['result']}",
                                                  body=json.dumps(result),
                                                  parent=av_section)

        if callout_section.body:
            result.add_section(callout)
        if av_section.subsections:
            result.add_section(av_section)

        return result

    def execute(self, request):
        request.result = Result()
        resp = self.session.get(f'/auth/api/sha256/{request.sha256}/json')
        if resp.ok:
            # File exists in Beaver, parse response
            self.log.info(f'Found {request.sha256} in Beaver database')
            request.result = self.parse_json(resp.json())
        return
