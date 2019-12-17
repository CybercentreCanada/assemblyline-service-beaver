import json

from assemblyline.common.exceptions import RecoverableError
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.result import Result, ResultSection, Classification, BODY_FORMAT
from beaver.beaver_datasource import Beaver as BeaverDatasource


class AvHitSection(ResultSection):
    def __init__(self, av_name, virus_name):
        title = f"{av_name} identified the file as {virus_name}"
        json_body = dict(
            av_name=av_name,
            virus_name=virus_name,
        )

        super(AvHitSection, self).__init__(
            title_text=title,
            body_format=BODY_FORMAT.KEY_VALUE,
            body=json.dumps(json_body),
            classification=Classification.UNRESTRICTED,
        )
        self.set_heuristic(3, signature=f'{av_name}.{virus_name}')
        self.add_tag('av.virus_name', virus_name)


class Beaver(ServiceBase):
    def __init__(self, config=None):
        super(Beaver, self).__init__(config)
        self.direct_db = self.config.get('x_api_key', None) is None
        self._connect_params = {}
        self.api_url = None
        self.connection = None

    def start(self):
        self._connect_params = {
            'host': self.config.get('host')
        }
        if self.direct_db:
            self._connect_params.update({
                'port': int(self.config.get('port')),
                'db': self.config.get('db'),
                'user': self.config.get('user'),
                'passwd': self.config.get('passwd')
            })
        else:
            self._connect_params.update({"x-api-key": self.config.get('x_api_key')})

        self.connection = BeaverDatasource(self.log, **self._connect_params)

    @staticmethod
    def lookup_callouts(response):
        results = response.get('callout', None)

        if not results:
            return None

        r_section = ResultSection('Sandbox Call-Outs')
        r_section.set_heuristic(4)
        analyser = ''
        r_sub_section = None
        for result in results[:10]:
            if analyser != result['analyser']:
                r_sub_section = ResultSection(f"{result['analyser']} (Analysed on {result['date']})", parent=r_section)
                analyser = result['analyser']

            channel = result['request']
            channel = f"({channel.split('~~')[0]})" if channel is not None else ""

            r_sub_section.add_line(f"{result['callout']}:{result['port']}{channel}")

            try:
                p1, p2, p3, p4 = result['callout'].split(".")
                if int(p1) <= 255 and int(p2) <= 255 and int(p3) <= 255 and int(p4) <= 255:
                    r_sub_section.add_tag('network.dynamic.ip', result['callout'])
            except ValueError:
                r_sub_section.add_tag('network.dynamic.domain', result['callout'])

            if result['port'] != 0:
                r_sub_section.add_tag('network.port', str(result['port']))

        if len(results) > 10:
            r_section.add_line(f"And {len(results) - 10} more...")
        return r_section

    @staticmethod
    def lookup_av_hits(response):
        results = response.get('antivirus', None)

        if not results:
            return None, []

        r_section = ResultSection('Anti-Virus Detections')

        r_section.add_line(f'Found {len(results)} AV hit(s).')
        for result in results:
            r_section.add_subsection(AvHitSection(result['scannerID'], result['name'], ))

        return r_section

    @staticmethod
    def lookup_source(response):
        result = response.get('source', None)
        if not result:
            return None

        if result['count'] > 0:
            json_body = dict(
                first_seen=result['first_seen'],
                last_seen=result['last_seen'],
                source_count=result['count'],
            )
            r_section = ResultSection('File Frequency', body_format=BODY_FORMAT.KEY_VALUE, body=json.dumps(json_body))
            return r_section

    @staticmethod
    def lookup_upatre_downloader(response):
        result = response.get('upatre', None)
        if not result:
            return None

        result = result[0]
        r_section = ResultSection('Upatre activity')
        r_section.set_heuristic(1)
        r_section.add_line(f"The file {result['firstSeen']} decodes to {result['decrypted_md5']} using "
                           f"XOR key {result['decryption_key']}")
        return r_section

    @staticmethod
    def lookup_spam_feed(response):
        result = response.get('spam_feed', None)
        if not result:
            return None

        result = result[0]
        r_section = ResultSection('SPAM feed')
        r_section.set_heuristic(2)
        r_section.add_line(f"Found {result['count']} related spam emails")
        r_section.add_line(f"\tFirst Seen: {result['first_seen']}")
        r_section.add_line(f"\tLast Seen: {result['last_seen']}")
        r_sub_section = ResultSection('Attachments', parent=r_section)
        r_sub_section.add_line(f"{result['filename']} - md5: {result['filename_md5']}")
        if result['attachment']:
            r_sub_section.add_line(f"\t{result['attachment']} - md5: {result['attachment_md5']}")
        return r_section

    def parse_direct_db(self, response):
        result = Result()

        res = self.lookup_source(response)
        if res:
            # Display source frequency if found
            result.add_section(res)

            res = self.lookup_upatre_downloader(response)
            if res:
                # Display Upatre data
                result.add_section(res)

            res = self.lookup_callouts(response)
            if res:
                # Display Call-Outs
                result.add_section(res)

            res = self.lookup_spam_feed(response)
            if res:
                # Display info from SPAM feed
                result.add_section(res)

            res = self.lookup_av_hits(response)
            if res:
                # Display Anti-virus result
                result.add_section(res)

        return result

    @staticmethod
    def parse_api(data):
        result = Result()

        # Info block
        hash_info = data.get('hashinfo', {})
        if not hash_info:
            return result

        json_body = dict()
        if 'receivedDate' in data.get('metadata'):
            json_body.update(dict(
                received_date=f"{data['metadata']['receivedDate'][:4]}-{data['metadata']['receivedDate'][4:6]}-"
                              f"{data['metadata']['receivedDate'][6:]}"
            ))

        json_body.update(dict(
            size=hash_info.get('filesize', ''),
            md5=hash_info.get('md5', ''),
            sha1=hash_info.get('sha1', ''),
            sha256=hash_info.get('sha256', ''),
            ssdeep_blocksize=hash_info.get('ssdeep_blocksize', ''),
            ssdeep_hash1=hash_info.get('ssdeep_hash1', ''),
            ssdeep_hash2=hash_info.get('ssdeep_hash2', ''),
        ))

        ResultSection(title_text='File Info', parent=result, body_format=BODY_FORMAT.KEY_VALUE,
                      body=json.dumps(json_body))

        callouts = data.get('callouts', [])
        if len(callouts) > 0:
            max_callouts = 10
            r_callouts = ResultSection('Sandbox Call-Outs')
            r_callouts.set_heuristic(4)
            analyser = ''
            r_call_sub_section = None

            reported_count = 0
            server = ''
            for callout in callouts:
                reported_count += 1
                if reported_count <= max_callouts:
                    ip = callout.get('ip', callout.get('hostIp', ''))
                    if analyser != ip:
                        title = f"{ip} (Analysed on {callout.get('addedOn', {}).get('data', 'Unknown date')})"
                        r_call_sub_section = ResultSection(title, parent=r_callouts)
                        analyser = ip

                    channel = callout['channel']
                    channel = f"({channel.split('~~')[0]})" if channel is not None else ""

                    server = callout.get('server', ip)
                    r_call_sub_section.add_line(f"{server}:{callout['port']}{channel}")

                try:
                    p1, p2, p3, p4 = server.split(".")
                    if int(p1) <= 255 and int(p2) <= 255 and int(p3) <= 255 and int(p4) <= 255:
                        r_call_sub_section.add_tag('network.dynamic.ip', server)
                except ValueError:
                    r_call_sub_section.add_tag('network.dynamic.domain', server)

                if callout['port'] != 0:
                    r_call_sub_section.add_tag('network.port', str(callout['port']))

            if len(callouts) > max_callouts:
                r_callouts.add_line(f"And {len(callouts) - 10} more...")
            result.add_section(r_callouts)

        av_results = data.get('av', [])
        if len(av_results) > 0:
            r_av_sec = ResultSection('Anti-Virus Detections')
            r_av_sec.add_line(f'Found {len(av_results)} AV hit(s).')
            for av_result in av_results:
                r_av_sec.add_subsection(AvHitSection(av_result['scannerID'], av_result['name']))
            result.add_section(r_av_sec)

        return result

    def execute(self, request):
        try:
            response = self.connection.query(request.md5)
        except BeaverDatasource.DatabaseException:
            raise RecoverableError("Query failed")
        if self.connection.direct_db:
            request.result = self.parse_direct_db(response)
        else:
            request.result = self.parse_api(response)
