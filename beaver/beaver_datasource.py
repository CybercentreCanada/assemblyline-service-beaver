import re
import threading
import traceback

import mysql.connector
import requests

HASH_RE = r'^[0-9a-fA-F]{32,64}$'
HASH_PATTERN = re.compile(HASH_RE)


callout_query = """\
SELECT
    analyser, callout, mc.port, cast(date(addedDate) as char) as date, channel as request
FROM
    malware_callouts mc
        JOIN
    malware_hash mh USING (md5)
WHERE
    mh.{field} = '{value}' AND
    callout not like '199.16.199%%%%' -- FireEye bogus IP
ORDER BY analyser, callout;
"""

av_hit_query = """\
SELECT
    ar.scannerID, an.name
FROM
    av_results ar
        JOIN
    malware_hash mh USING (md5)
        JOIN
    av_names an USING (nameID)
WHERE
    mh.{field} = '{value}'
GROUP BY scannerID;
"""

source_query = """\
SELECT
    cast(date(min(receivedDate)) as char) as first_seen,
    cast(date(max(receivedDate)) as char) as last_seen,
    count(sourceID) as count,
    filesize as size,
    md5,
    sha1,
    sha256
FROM
    mfs.samples
        JOIN
    malware_hash mh USING (md5)
WHERE
    mh.{field} = '{value}';
"""

upatre_query = """\
SELECT
    h.md5, u.decrypted_md5, u.decryption_key
FROM
    malware_upatre_decrypter u
        join
    malware_hash h ON (h.md5 = u.md5 or h.md5 = u.decrypted_md5)
WHERE
    decrypted_md5 is not null
        and h.{field} = '{value}';
"""

spam_feed_query = """\
SELECT
    cast(date(min(e1.id)) as char) as first_seen,
    cast(date(max(e1.id)) as char) as last_seen,
    e1.filename as attachment,
    e1.md5 as attachment_md5,
    e2.filename,
    e2.md5 as filename_md5,
    count(e1.id) as count
FROM
    malware_hash mh
        JOIN
    efs.samples e1 ON (mh.md5 = e1.md5)
        LEFT JOIN
    efs.samples e2 ON (e2.md5 = e1.parent_md5 OR e2.md5 = e1.parent_md5)
WHERE
    mh.{field} = '{value}'
GROUP BY e1.md5;
"""


def _hash_type(value):
    if HASH_PATTERN.match(value):
        return {
            32: "md5", 40: "sha1", 64: "sha256"
        }.get(len(value), "invalid")
    else:
        return "invalid"


class Beaver:
    class DatabaseException(Exception):
        pass

    Name = "CCIRC Malware Database"

    def __init__(self, log, **kw):
        self.log = log
        self.params = {
            k: kw[k] for k in ('host',)
        }

        self.api_url = None
        self.direct_db = False
        self.session = None

        if 'db' in kw and 'port' in kw:
            self.direct_db = True
            self.params.update({k: kw[k] for k in ('db', 'port', 'passwd', 'user')})
        else:
            self.api_url = f"{kw['host']}/1.0/%s/%s/report"
            self.xapikey = kw['x-api-key']

        self.tls = threading.local()
        self.tls.connection = None

    def connect(self):
        try:
            self.tls.connection = mysql.connector.connect(
                connect_timeout=10,
                **self.params
            )
        except mysql.connector.Error:
            self.tls.connection = None
            self.log.warning(f"Could not connect to database: {traceback.format_exc()}")
            raise self.DatabaseException()
        except AttributeError:
            self.tls.connection = None
            raise self.DatabaseException("TLS not initialized")

    # noinspection PyUnresolvedReferences
    def _query(self, sql, hash_type, value, fetchall=True):
        results = []

        if not hasattr(self.tls, "connection"):
            self.tls.connection = None

        if self.tls.connection is None:
            self.connect()
        cursor = None
        try:
            cursor = self.tls.connection.cursor(dictionary=True)
            cursor.execute(sql.format(field=hash_type, value=value))
            if fetchall:
                results = cursor.fetchall()
            else:
                result = cursor.fetchone()
                if result:
                    results = [result]
            cursor.close()
            cursor = None
        except MySQLdb.Error:
            if cursor is not None:
                try:
                    cursor.close()
                except MySQLdb.ProgrammingError:
                    pass
            try:
                self.tls.connection.close()
            except MySQLdb.Error:
                pass
            self.tls.connection = None
            self.log.warning(f"Could not query database: {traceback.format_exc()}")
            raise self.DatabaseException()

        return results

    def parse(self, results):
        if self.direct_db:
            item = self.parse_db(results)
        else:
            item = self.parse_api(results)

        if item:
            return [item]

        return []

    @staticmethod
    def parse_api(results):
        if not results:
            return []

        hash_info = results.get('hashinfo', {})
        if not hash_info:
            return []

        rdate = results.get('metadata', {}).get('receivedDate')

        if rdate:
            first_seen = f"{rdate[:4]}-{rdate[4:6]}-{rdate[6:]}T00:00:00Z"
        else:
            first_seen = "1970-01-01T00:00:00Z"

        data = {
            "first_seen": first_seen,
            "last_seen": first_seen,  # No last_seen is
            "md5": hash_info.get('md5', ""),
            "sha1": hash_info.get('sha1', ""),
            "sha256": hash_info.get('sha256', ""),
            "size": hash_info.get('filesize', ""),
            "raw": results
        }

        malicious = any(results.get(x, None) for x in (
            'av'
        ))

        return {
            "confirmed": malicious,
            "data": data,
            "description": f"File found in the {Beaver.Name}.",
            "malicious": malicious,
        }

    @staticmethod
    def parse_db(results):
        data = results.pop('source', {})
        count = data.get('count', 0)
        if not count:
            return []

        malicious = any(results.get(x, None) for x in (
            'antivirus', 'callout', 'spam_feed', 'upatre',
        ))

        data.update(results)

        return {
            "confirmed": malicious,
            "data": data,
            "description": f"File found {count} time(s) in the {Beaver.Name}.",
            "malicious": malicious,
        }

    def query_api(self, hash_type, value):
        if self.session is None:
            # noinspection PyUnresolvedReferences

            self.session = requests.Session()

        response = self.session.get(
            self.api_url % (hash_type, value),
            headers={'X-API-Key': self.xapikey}
        )

        # noinspection PyBroadException
        try:
            response.raise_for_status()  # Raise exception when status_code != 200.
        except Exception:
            error = response.json()
            error_code = response.status_code
            if error_code in (204, 404):  # No data for file or file not found
                return {}
            else:
                raise Exception(f"[{error_code}] {error.get('error', 'Unknown error')}")

        return response.json()

    def query_db(self, hash_type, value):
        results = {}

        result = self._query(source_query, hash_type, value, fetchall=False)
        if not result:
            return results

        results['source'] = result[0]

        results['antivirus'] = self._query(av_hit_query, hash_type, value)
        results['callout'] = self._query(callout_query, hash_type, value)
        results['spam_feed'] = self._query(spam_feed_query, hash_type, value, fetchall=False)
        results['upatre'] = self._query(upatre_query, hash_type, value, fetchall=False)

        return results

    def query(self, value, **kw):
        hash_type = _hash_type(value)
        value = value.lower()

        if self.direct_db:
            return self.query_db(hash_type, value)
        else:
            return self.query_api(hash_type, value)
