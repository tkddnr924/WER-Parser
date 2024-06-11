from typing import Dict, List, Tuple
from pathlib import Path
import re

from .wer import WER
from .utils import get_report_file, sort_event_time

from rich import console, table
from tqdm import tqdm

class Parser:
    temp_sig = []
    temp_dynamic = []
    temp_response = []
    temp_ui = []
    temp_modules = []
    temp_state = []
    temp_os = []

    parsed_data: List[WER] = []
    _console = console.Console()

    def __init__(self, file_path: str):
        self._read_report(get_report_file(file_path))
    
    def view_data(self):
        _table = table.Table(title="WER(Windows Error Reporting)")
        columns = ["Event Time", "Program Name", "Event Type", "Signature"]

        for column in columns:
            _table.add_column(column)

        self.parsed_data.sort(key=sort_event_time, reverse=True)

        # "\n".join([f"{item['Name']}: {item['Value']}" for item in wer.signature])

        for wer in self.parsed_data:
            _table.add_row(
                wer.event_time_readable,
                wer.app_name,
                wer.event_type,
                wer.signature.error_module_name,
                style='bright_green')

        self._console.print(_table)
    
    def _read_report(self, reports: List) -> None:
        with tqdm(total=len(reports), desc='Parse WER') as pbar:
            for report in reports:
                self._parse_report(report)
                pbar.update(1)

    def _parse_report(self, report: str):
        with open(Path(report), 'r', encoding="utf16") as _file:
            result = {}
            for line in _file.readlines():
                line = line.replace("\n", "")
                line = line.replace("\r\n", "")
                
                if "Response." in line:
                    self.temp_response.append(line)
                elif "DynamicSig[" in line:
                    self.temp_dynamic.append(line)
                elif "Sig[" in line:
                    self.temp_sig.append(line)
                elif "UI[" in line:
                    self.temp_ui.append(line)
                elif "LoadedModule[" in line:
                    self.temp_modules.append(line)
                elif "State[" in line:
                    self.temp_state.append(line)
                elif "OsInfo[" in line:
                    self.temp_os.append(line)
                else:
                    key, value = self._parse_wer(line)
                    result[key] = value
            temp_data = self._parse_temp()
            result.update(temp_data)

            wer_report = WER({ "file_path": report, "data": result })
            self.parsed_data.append(wer_report)
            self._clear_temp()


    def _parse_wer(self, line: str) -> Tuple:
        key, value = line.split("=")
        return key, value
    
    def _clear_temp(self):
        self.temp_response = []
        self.temp_sig = []
        self.temp_dynamic = []
        self.temp_ui = []
        self.temp_modules = []
        self.temp_state = []
        self.temp_os = []
    
    def _parse_temp(self) -> Dict:
        result = {}

        if len(self.temp_response) > 0:
            response_data = self._parse_response()
            result.update(response_data)

        if len(self.temp_sig) > 0:
            signature = self._parse_signature()
            result.update(signature)

        if len(self.temp_dynamic) > 0:
            dynamic = self._parse_dynamic()
            result.update(dynamic)

        if len(self.temp_ui) > 0:
            ui = self._parse_ui()
            result.update(ui)

        if len(self.temp_modules) > 0:
            modules = self._parse_modules()
            result.update(modules)
        
        if len(self.temp_state) > 0:
            state = self._parse_state()
            result.update(state)

        if len(self.temp_os) > 0:
            os_info = self._parse_os()
            result.update(os_info)

        return result

    def _parse_response(self) -> Dict:
        result = {"Response": {}}
        pattern = r'Response\.(?P<key>\w+)=(?P<value>\S+)'

        for response in self.temp_response:
            matched = re.match(pattern, response)
            result['Response'][matched.group('key')] = matched.group('value')

        return result

    def _parse_signature(self) -> Dict:
        result = {"Sig": []}
        pattern = r'Sig\[(\d+)\]\.Name=(?P<name>.*?)\nSig\[\d+\]\.Value=(?P<value>.*?)\n'

        matches = re.findall(pattern, "\n".join(self.temp_sig) + "\n")

        for matched in matches:
            result["Sig"].append({ "Name": matched[1], "Value": matched[2]})

        return result

    def _parse_dynamic(self) -> Dict:
        result = { "DynamicSig": []}
        pattern = r'DynamicSig\[(\d+)\]\.Name=(?P<name>.*?)\nDynamicSig\[\d+\]\.Value=(?P<value>.*?)\n'

        matches = re.findall(pattern, "\n".join(self.temp_dynamic) + "\n")

        for matched in matches:
            result["DynamicSig"].append({ "Name": matched[1], "Value": matched[2]})

        return result
    
    def _parse_ui(self) -> Dict:
        result = { "UI": [] }
        pattern = r'UI\[\d+\]=(?P<path>.*)\n'

        matches = re.findall(pattern, "\n".join(self.temp_ui) + "\n")

        for matched in matches:
            result["UI"].append(matched)
        return result
    
    def _parse_modules(self) -> Dict:
        result = { "LoadedModule": []}
        pattern = r"LoadedModule\[\d+\]=(?P<path>.*)\n"

        matches = re.findall(pattern, "\n".join(self.temp_modules) + "\n")

        for matched in matches:
            result['LoadedModule'].append(matched)
        return result
    
    def _parse_state(self) -> Dict:
        result = { "State": [] }
        pattern = r'State\[(\d+)\]\.Key=(?P<key>.*?)\nState\[\d+\]\.Value=(?P<value>.*?)\n'

        matches = re.findall(pattern, "\n".join(self.temp_state) + "\n")

        for matched in matches:
            result["State"].append({ "Key": matched[1], "Value": matched[2] })

        return result
    
    def _parse_os(self) -> Dict:
        result = { "OsInfo": [] }
        pattern = r'OsInfo\[(\d+)\]\.Key=(?P<key>.*?)\nOsInfo\[\d+\]\.Value=(?P<value>.*?)\n'

        matches = re.findall(pattern, "\n".join(self.temp_os) + "\n")

        for matched in matches:
            result["OsInfo"].append({ "Key": matched[1], "Value": matched[2] })

        return result
    
