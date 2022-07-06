#!/usr/bin/env python3

from argparse import ArgumentParser
from configparser import ConfigParser
from datetime import datetime
import email
import gzip
import io
import socket
import sys
import xml.etree.ElementTree as ET
from zipfile import ZipFile
from imapclient import IMAPClient


class DmarcReportRecord:
    def __init__(self, from_source: str, from_domain: str, count: int,
                 dkim: str, spf: str, disposition: list):
        self.from_source = from_source
        self.from_domain = from_domain
        self.count = count
        self.dkim = dkim
        self.spf = spf
        self.disposition = disposition

    def is_failed(self):
        return self.dkim != "pass" or self.spf != "pass"


class DmarcReport:
    def __init__(self, domain: str, source: str, report_id: str,
                 date_begin: str, date_end: str):
        self.domain = domain
        self.source = source
        self.report_id = id
        self.date_begin = date_begin
        self.date_end = date_end
        self.records = []

    def add_record(self, record: DmarcReportRecord):
        self.records.append(record)

    def get_total_count(self):
        count = 0
        for record in self.records:
            count += record.count
        return count

    def get_passed_count(self):
        count = 0
        for record in self.records:
            if not record.is_failed():
                count += record.count
        return count


class DmarcSourceReports(dict):
    def add_report(self, report: DmarcReport):
        if report.source not in self.keys():
            self[report.source] = []
        self[report.source].append(report)

    def aggregate_reports(self, source: str):
        result_report = None
        for report in self[source]:
            if result_report is None:
                result_report = report
                result_report.report_id = None
            else:
                if result_report.date_begin > report.date_begin:
                    result_report.date_begin = report.date_begin
                if result_report.date_end < report.date_end:
                    result_report.date_end = report.date_end
                for record in report.records:
                    result_report.add_record(record)

        # Aggregate failed records in report
        result_report.failed_records = RecordAggregate.FromSource()
        for record in result_report.records:
            if not record.is_failed():
                continue
            result_report.failed_records.add_record(record)

        return result_report


class DmarcDomainReports(dict):
    def add_report(self, report: DmarcReport):
        if report.domain not in self.keys():
            self[report.domain] = DmarcSourceReports()
        self[report.domain].add_report(report)


class RecordAggregate:
    class RecordAggregate:
        def __init__(self):
            self.count = 0
            self.dkim = []
            self.spf = []
            self.disposition = []

        def add_record(self, record: DmarcReportRecord):
            self.count += record.count
            if record.dkim not in self.dkim:
                self.dkim.append(record.dkim)
            if record.spf not in self.spf:
                self.spf.append(record.spf)
            if record.disposition not in self.disposition:
                self.disposition.append(record.disposition)

    class FromDomain(dict):
        def add_record(self, record: DmarcReportRecord):
            if record.from_domain not in self.keys():
                self[record.from_domain] = RecordAggregate.RecordAggregate()
            self[record.from_domain].add_record(record)

    class FromSource(dict):
        def add_record(self, record: DmarcReportRecord):
            if record.from_source not in self.keys():
                self[record.from_source] = RecordAggregate.FromDomain()
            self[record.from_source].add_record(record)


def parse_xml_report(data):
    xml = ET.ElementTree(ET.fromstring(data))

    report_domain = xml.find("policy_published/domain").text
    report_source = xml.find("report_metadata/org_name").text
    report_id = xml.find("report_metadata/report_id").text
    report_date_begin = int(xml.find("report_metadata/date_range/begin").text)
    report_date_end = int(xml.find("report_metadata/date_range/end").text)

    report = DmarcReport(report_domain, report_source,
                         report_id, report_date_begin, report_date_end)

    for record in xml.findall("record"):
        record_source_ip = record.find("row/source_ip").text
        try:
            record_source_domain = socket.gethostbyaddr(record_source_ip)[0]
            record_source = "{} ({})".format(
                record_source_domain, record_source_ip)
        except Exception:
            record_source = record_source_ip

        record_from_domain = record.find("identifiers/header_from").text
        record_count = int(record.find("row/count").text)
        record_dkim = record.find("row/policy_evaluated/dkim").text
        record_spf = record.find("row/policy_evaluated/spf").text
        record_disposition = record.find(
            "row/policy_evaluated/disposition").text

        record = DmarcReportRecord(record_source, record_from_domain,
                                   record_count, record_dkim, record_spf,
                                   record_disposition)
        report.add_record(record)

    return report


def parse_email_reports(message):
    reports = []

    for part in message.walk():
        # DMARC reports are not send as "multipart"
        if part.is_multipart():
            continue

        # DMARC reports are using "Content-Disposition: attachment;"
        if part.get_content_disposition() != "attachment":
            continue

        # Parse attachment
        content_type = part.get_content_type()
        data = None
        if content_type == "application/zip":
            zip_bytes = io.BytesIO(part.get_payload(decode=True))
            zip_file = ZipFile(zip_bytes)
            with zip_file.open(zip_file.namelist()[0], 'r') as file:
                data = file.read()
        elif content_type == "application/gzip":
            data = gzip.decompress(part.get_payload(decode=True))

        if not data:
            continue

        reports.append(parse_xml_report(data))

    return reports


def fetch_emails(host, username, password, port=None, ssl=True, folder="INBOX",
                 read_all=False):
    domain_reports = DmarcDomainReports()

    with IMAPClient(host, port, use_uid=True, ssl=ssl) as server:
        server.login(username, password)
        server.select_folder(folder)

        print()
        print("Analyzing DMARC reports in IMAP folder '{}' (user: {})".format(
            folder, username))
        print()

        if read_all:
            # Read all reports in the selected folder
            messages = server.search()
        else:
            # Read only the unprocessed/unread reports
            messages = server.search([u'UNSEEN'])

        # Fetch emails
        if messages:
            response = server.fetch(
                messages, ['FLAGS', 'BODY', 'ENVELOPE', 'RFC822'])
            for _, data in response.items():
                message = email.message_from_bytes(data[b'RFC822'])
                reports = parse_email_reports(message)

                for report in reports:
                    domain_reports.add_report(report)

    return domain_reports


def print_report(report: DmarcReport):
    passed_count = report.get_passed_count()
    total_count = report.get_total_count()
    print("        Period from {} to {}".format(datetime.fromtimestamp(
        report.date_begin), datetime.fromtimestamp(report.date_end)))
    print("        Passed {}/{}".format(passed_count, total_count))
    if passed_count < total_count:
        print("        {} FAILED!".format(total_count - passed_count))
        if not hasattr(report, 'failed_records'):
            return
        print("")
        for from_source in report.failed_records:
            print("        Sent by {}:".format(from_source))
            for from_domain in report.failed_records[from_source]:
                record = report.failed_records[from_source][from_domain]
                print("            {} from domain {}".format(
                    record.count, from_domain))
                print("            DKIM: {}, SPF: {}, disposition: {}".format(
                    sorted(record.dkim), sorted(record.spf),
                    sorted(record.disposition)))


def print_domain_reports(domain_reports: DmarcDomainReports):
    for domain in domain_reports:
        print("Reports for domain {}:".format(domain))
        for source in domain_reports[domain]:
            print("    Report source {}:".format(source))
            print_report(domain_reports[domain].aggregate_reports(source))
            print()


def main():
    # Parse arguments
    parser = ArgumentParser(
        description="DMARC reports aggregator from IMAP folder")
    parser.add_argument("-c", "--config-file",
                        help="a path to the configuration file", required=True)
    parser.add_argument("--all", action="store_true",
                        help="read all reports in the IMAP foder")
    args = parser.parse_args()

    # Parse configuration
    config = ConfigParser()
    config.read(args.config_file)

    if "imap" not in config.sections():
        sys.exit("No 'imap' section in the config file")
    imap_config = config["imap"]

    if "host" not in imap_config:
        sys.exit("No 'host' parameter in 'imap' section of the config file")
    if "username" not in imap_config:
        sys.exit(
            "No 'username' parameter in 'imap' section of the config file")
    if "password" not in imap_config:
        sys.exit(
            "No 'password' parameter in 'imap' section of the config file")

    host = imap_config["host"]
    username = imap_config["username"]
    password = imap_config["password"]
    port = imap_config["port"] if "port" in imap_config else None
    ssl = imap_config["ssl"] if "ssl" in imap_config else True
    folder = imap_config["folder"] if "folder" in imap_config else "INBOX"

    # Analyze reports
    domain_reports = fetch_emails(host=host, username=username,
                                  password=password, port=port, ssl=ssl,
                                  folder=folder, read_all=args.all)
    print_domain_reports(domain_reports)


if __name__ == "__main__":
    main()
