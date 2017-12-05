#!/usr/bin/env python

from assemblyline.common.context import Context
from assemblyline.al.common.result import Result, ResultSection, SCORE, Classification, Tag, TAG_TYPE, TAG_WEIGHT
from assemblyline.al.common.av_result import VirusHitTag
from assemblyline.al.service.base import ServiceBase, Category
from assemblyline.common.exceptions import RecoverableError

BeaverDatasource = None


class AvHitSection(ResultSection):
    def __init__(self, av_name, virus_name, score):
        title = '%s identified the file as %s' % (av_name, virus_name)
        super(AvHitSection, self).__init__(
            title_text=title,
            score=score,
            classification=Classification.UNRESTRICTED)


class Beaver(ServiceBase):
    SERVICE_ACCEPTS = '.*'
    SERVICE_ENABLED = True
    SERVICE_CATEGORY = Category.STATIC_ANALYSIS
    SERVICE_REVISION = ServiceBase.parse_revision('$Id$')
    SERVICE_VERSION = '1'
    SERVICE_DEFAULT_CONFIG = {
        "host": "127.0.0.1",
        "user": "user",
        "passwd": "password",
        "port": 3306,
        "db": "beaver",
        "x-api-key": None
    }
    SERVICE_DESCRIPTION = "Performs hash lookups against the CCIRC Malware Database."
    SERVICE_CPU_CORES = 0.05
    SERVICE_CPU_RAM = 64

    def __init__(self, cfg=None):
        super(Beaver, self).__init__(cfg)
        self.direct_db = cfg.get('x-api-key', None) is None
        self._connect_params = {}
        self.api_url = None
        self.connection = None

    def start(self):
        self._connect_params = {
            'host': self.cfg.get('host')
        }
        if self.direct_db:
            self._connect_params.update({
                'port': int(self.cfg.get('port')),
                'db': self.cfg.get('db'),
                'user': self.cfg.get('user'),
                'passwd': self.cfg.get('passwd')
            })
        else:
            self._connect_params.update({"x-api-key": self.cfg.get('x-api-key')})

        self.connection = BeaverDatasource(self.log, **self._connect_params)

    # noinspection PyUnresolvedReferences
    def import_service_deps(self):
        global BeaverDatasource
        from al_services.alsvc_beaver.datasource.beaver import Beaver as BeaverDatasource

    @staticmethod
    def lookup_callouts(response):
        results = response.get('callout', None)

        if not results:
            return None, []

        tags = []
        r_section = ResultSection(title_text='Sandbox Call-Outs')
        r_section.score = SCORE.HIGH
        analyser = ''
        r_sub_section = None
        for result in results[:10]:
            if analyser != result['analyser']:
                title = '%s (Analysed on %s)' % (result['analyser'], result['date'])
                r_sub_section = ResultSection(title_text=title, parent=r_section)
                analyser = result['analyser']

            channel = result['request']
            if channel is not None:
                channel = "(%s)" % channel.split('~~')[0]
            else:
                channel = ""

            r_sub_section.add_line("{0:s}:{1:d}{2:s}".format(result['callout'], result['port'], channel))

            try:
                p1, p2, p3, p4 = result['callout'].split(".")
                if int(p1) <= 255 and int(p2) <= 255 and int(p3) <= 255 and int(p4) <= 255:
                    tags.append(Tag(TAG_TYPE.NET_IP, result['callout'], TAG_WEIGHT.MED, context=Context.BEACONS))
            except ValueError:
                tags.append(Tag(TAG_TYPE.NET_DOMAIN_NAME, result['callout'], TAG_WEIGHT.MED, context=Context.BEACONS))

            if result['port'] != 0:
                tags.append(Tag(TAG_TYPE.NET_PORT, str(result['port']), TAG_WEIGHT.MED, context=Context.BEACONS))

        if len(results) > 10:
            r_section.add_line("And %s more..." % str(len(results) - 10))
        return r_section, tags

    @staticmethod
    def lookup_av_hits(response):
        results = response.get('antivirus', None)

        if not results:
            return None, []

        tags = []
        r_section = ResultSection(title_text='Anti-Virus Detections')

        r_section.add_line('Found %d AV hit(s).' % len(results))
        for result in results:
            r_section.add_section(AvHitSection(result['scannerID'], result['name'], SCORE.SURE))
            tags.append(VirusHitTag(result['name'], context="scanner:%s" % result['scannerID']))

        return r_section, tags

    @staticmethod
    def lookup_source(response):
        result = response.get('source', None)
        if not result:
            return None

        if result['count'] > 0:
            r_section = ResultSection(title_text='File Frequency')
            r_section.score = SCORE.NULL
            r_section.add_line('First Seen: %s' % result['first_seen'])
            r_section.add_line('Last Seen: %s' % result['last_seen'])
            r_section.add_line('Source Count: %d' % result['count'])
            return r_section

    @staticmethod
    def lookup_upatre_downloader(response):
        result = response.get('upatre', None)
        if not result:
            return None

        result = result[0]
        r_section = ResultSection(title_text='Upatre activity')
        r_section.score = SCORE.VHIGH
        r_section.add_line('The file %s decodes to %s using XOR key %s' % (result['firstSeen'],
                                                                           result['decrypted_md5'],
                                                                           result['decryption_key']))
        return r_section

    @staticmethod
    def lookup_spam_feed(response):
        result = response.get('spam_feed', None)
        if not result:
            return None

        result = result[0]
        r_section = ResultSection(title_text='SPAM feed')
        r_section.score = SCORE.HIGH
        r_section.add_line('Found %d related spam emails' % result['count'])
        r_section.add_line('\tFirst Seen: %s' % result['first_seen'])
        r_section.add_line('\tLast Seen: %s' % result['last_seen'])
        r_sub_section = ResultSection(title_text='Attachments', parent=r_section)
        r_sub_section.add_line('%s - md5: %s' % (result['filename'], result['filename_md5']))
        if result['attachment']:
            r_sub_section.add_line('\t%s - md5: %s' % (result['attachment'], result['attachment_md5']))
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

            res, tags = self.lookup_callouts(response)
            if res:
                # Display Call-Outs
                result.add_section(res)

                # Add domain, ip and port tags
                _ = [result.append_tag(tag) for tag in tags]

            res = self.lookup_spam_feed(response)
            if res:
                # Display info from SPAM feed
                result.add_section(res)

            res, tags = self.lookup_av_hits(response)
            if res:
                # Display Anti-virus result
                result.add_section(res)

                # Add Virus Tags
                _ = [result.append_tag(tag) for tag in tags]

        return result

    @staticmethod
    def parse_api(data):
        result = Result()

        # Info block
        hash_info = data.get('hashinfo', {})
        if not hash_info:
            return result
        r_info = ResultSection(title_text='File Info')
        r_info.score = SCORE.NULL
        if 'receivedDate' in data.get('metadata'):
            r_info.add_line('Received Data: %s-%s-%s' % (data['metadata']['receivedDate'][:4],
                                                         data['metadata']['receivedDate'][4:6],
                                                         data['metadata']['receivedDate'][6:]))
        r_info.add_line('Size: %s' % hash_info.get('filesize', ""))
        r_info.add_line('MD5: %s' % hash_info.get('md5', ""))
        r_info.add_line('SHA1: %s' % hash_info.get('sha1', ""))
        r_info.add_line('SHA256: %s' % hash_info.get('sha256', ""))
        r_info.add_line('SSDeep Blocksize: %s' % hash_info.get('ssdeep_blocksize', ""))
        r_info.add_line('SSDeep Hash1: %s' % hash_info.get('ssdeep_hash1', ""))
        r_info.add_line('SSDeep Hash2: %s' % hash_info.get('ssdeep_hash2', ""))
        result.add_result(r_info)

        callouts = data.get('callouts', [])
        if len(callouts) > 0:
            max_callouts = 10
            r_callouts = ResultSection(title_text='Sandbox Call-Outs')
            r_callouts.score = SCORE.VHIGH
            analyser = ''
            r_call_sub_section = None

            reported_count = 0
            server = ''
            for callout in callouts:
                reported_count += 1
                if reported_count <= max_callouts:
                    ip = callout.get('ip', callout.get('hostIp', ''))
                    if analyser != ip:
                        title = '%s (Analysed on %s)' % (ip, callout.get('addedOn', {}).get('data', 'Unknown date'))
                        r_call_sub_section = ResultSection(title_text=title, parent=r_callouts)
                        analyser = ip

                    channel = callout['channel']
                    if channel is not None:
                        channel = "(%s)" % channel.split('~~')[0]
                    else:
                        channel = ""

                    server = callout.get('server', ip)
                    r_call_sub_section.add_line("{0:s}:{1:d}{2:s}".format(server, callout['port'], channel))

                try:
                    p1, p2, p3, p4 = server.split(".")
                    if int(p1) <= 255 and int(p2) <= 255 and int(p3) <= 255 and int(p4) <= 255:
                        result.append_tag(
                            Tag(TAG_TYPE.NET_IP, server, TAG_WEIGHT.MED, context=Context.BEACONS))
                except ValueError:
                    result.append_tag(Tag(TAG_TYPE.NET_DOMAIN_NAME, server, TAG_WEIGHT.MED,
                                          context=Context.BEACONS))

                if callout['port'] != 0:
                    result.append_tag(Tag(TAG_TYPE.NET_PORT, str(callout['port']),
                                          TAG_WEIGHT.MED, context=Context.BEACONS))

            if len(callouts) > max_callouts:
                r_callouts.add_line("And %s more..." % str(len(callouts) - 10))
            result.add_result(r_callouts)

        av_results = data.get('av', [])
        if len(av_results) > 0:
            r_av_sec = ResultSection(title_text='Anti-Virus Detections')
            r_av_sec.add_line('Found %d AV hit(s).' % len(av_results))
            for av_result in av_results:
                r_av_sec.add_section(AvHitSection(av_result['scannerID'], av_result['name'], SCORE.SURE))
                result.append_tag(VirusHitTag(av_result['name'], context="scanner:%s" % av_result['scannerID']))
            result.add_result(r_av_sec)

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
