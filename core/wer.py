from typing import Dict
from .utils import date_from_webkit
from .constant import WER_REPORT_TYPE, WER_CONSENT
from pydantic import BaseModel, Field

DEFAULT_STRING = "-"

class WER:
    directory_name: str = ""

    def __init__(self, data: Dict):
        self._split_file_path(data['file_path'])
        self._insert_parsed_data(data['data'])
        self.original = data['data']
        return
    
    def _split_file_path(self, file_path: str):
        splited = file_path.split("\\")

        self.file_name = splited[-1]
        self.file_dir = splited[-2]

        temp = self.file_dir.split("_")

        if len(temp) == 5:
            self.dir_event = temp[0]
            self.program_name = temp[1]
            self.first_hash = temp[2]
            self.second_hash = temp[3]
            self.report_id = temp[4]
        elif len(temp) ==6:
            self.dir_event = temp[0]
            self.program_name = temp[1] + temp[2]
            self.first_hash = temp[3]
            self.second_hash = temp[4]
            self.report_id = temp[5]
        return
    
    def _insert_parsed_data(self, report: Dict):
        self.version = report['Version']
        self.event_type = report['EventType']
        self.event_time = report['EventTime']
        self.event_time_readable = date_from_webkit(self.event_time)
        self.report_type = report.get("ReportType", DEFAULT_STRING)
        self.report_type_decription = WER_REPORT_TYPE[report['ReportType']] if "ReportType" in report else DEFAULT_STRING
        self.consent = WER_CONSENT[report['Consent']]
        self.upload_time = report['UploadTime']
        self.upload_time_readable = date_from_webkit(self.upload_time)
        self.report_flags = report.get("ReportFlags", DEFAULT_STRING)
        self.report_status = report['ReportStatus']
        self.report_identifier = report['ReportIdentifier']
        self.integrator_report_identifier = report.get("IntegratorReportIdentifier", DEFAULT_STRING)
        self.wow64_host = report['Wow64Host']
        self.app_session_guid = report['AppSessionGuid']
        self.boot_id = report['BootId']
        self.heap_dump_attached = report.get("HeapdumpAttached", "")
        self.target_as_id = report['TargetAsId']
        self.target_app_id = report.get('TargetAppId', DEFAULT_STRING)
        self.target_app_ver = report.get('TargetAppVer', DEFAULT_STRING)
        self.user_impact_vector = report.get("UserImpactVector", "")
        self.is_fatal = report.get('IsFatal', "")
        self.friendly_event_name = report['FriendlyEventName']
        self.consent_key = report['ConsentKey']
        self.app_name = report['AppName']
        self.ns_partner = report.get('NsPartner', "")
        self.ns_group = report.get("NsGroup", "")
        self.application_identity = report['ApplicationIdentity']
        self.metadata_hash = report['MetadataHash']
        self.response = WerResponse(report['Response'])

        _signature: Dict = self._convert_signature(report['Sig'])
        self.signature = WerSignature(**_signature)

        self.dynamic_signature = report['DynamicSig']
        self.ui = report.get('UI', [])
        self.loaded_module = report.get('LoadedModule', [])
        self.state = report.get('State', [])
        self.os_info = report['OsInfo']
        self.original_file_name = report.get("OriginalFilename", DEFAULT_STRING)

    def _convert_signature(self, signature) -> Dict:
        field_mapping = {
            "응용 프로그램 이름": "application_name",
            "Application Name": "application_name",
            "응용 프로그램 버전": "application_version",
            "Application Version": "application_version",
            "응용 프로그램 타임스탬프": "application_timestamp",
            "Application Timestamp": "application_timestamp",
            "오류 모듈 이름": "error_module_name",
            "오류 모듈 버전": "error_module_version",
            "오류 모듈 타임스탬프": "error_module_timestamp",
            "예외 코드": "exception_code",
            "예외 오프셋": "exception_offset",
            "예외 데이터": "exception_data",
            "Hang Signature": "hang_signature",
            "Hang Type": "hang_type",
            "Package Full Name": "package_full_name",
            "ClientAppId": "client_app_id",
            "HResult": "h_result",
            "OSVersion": "os_version",
            "OSRevision": "os_revision",
            "DeviceClass": "device_class",
            "ProductHash": "product_hash"
        }

        return {field_mapping[item['Name']]: item['Value'] for item in signature}


class WerResponse:
    def __init__(self, response: Dict):
        self.bucket_id = response.get('BucketId', "")
        self.bucket_table = response.get('BucketTable', "")
        self.legacy_bucket_id = response.get("LegacyBucketId", "")
        self.type = response.get('type', "")

class WerSignature(BaseModel):
    application_name: str = Field(default=DEFAULT_STRING)
    application_version: str = Field(default=DEFAULT_STRING)
    application_timestamp: str = Field(default=DEFAULT_STRING)
    error_module_name: str = Field(default=DEFAULT_STRING)
    error_module_version: str= Field(default=DEFAULT_STRING)
    error_module_timestamp: str= Field(default=DEFAULT_STRING)
    exception_code: str= Field(default=DEFAULT_STRING)
    exception_offset: str= Field(default=DEFAULT_STRING)
    exception_data: str= Field(default=DEFAULT_STRING)
    hang_signature: str= Field(default=DEFAULT_STRING)
    hang_type: str= Field(default=DEFAULT_STRING)
    package_full_name: str= Field(default=DEFAULT_STRING)
    client_app_id: str= Field(default=DEFAULT_STRING)
    h_result: str= Field(default=DEFAULT_STRING)
    os_version: str= Field(default=DEFAULT_STRING)
    os_revision: str= Field(default=DEFAULT_STRING)
    device_class: str= Field(default=DEFAULT_STRING)
    product_hash: str= Field(default=DEFAULT_STRING)