#! /usr/bin/env python3
# -*- coding: utf-8 -*-

# Flake8LintCLI.py (Python Tool Wrapper)
# ..................................
# Copyright (c) 2024-2025, Mr. Walls
# ..................................
# Licensed under MIT (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# ..........................................
# https://www.github.com/reactive-firewall/flake8-cq/LICENSE
# ..........................................
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Disclaimer of Warranties.
# A. YOU EXPRESSLY ACKNOWLEDGE AND AGREE THAT, TO THE EXTENT PERMITTED BY
#    APPLICABLE LAW, USE OF THIS SHELL SCRIPT AND ANY SERVICES PERFORMED
#    BY OR ACCESSED THROUGH THIS SHELL SCRIPT IS AT YOUR SOLE RISK AND
#    THAT THE ENTIRE RISK AS TO SATISFACTORY QUALITY, PERFORMANCE, ACCURACY AND
#    EFFORT IS WITH YOU.
#
# B. TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW, THIS SHELL SCRIPT
#    AND SERVICES ARE PROVIDED "AS IS" AND "AS AVAILABLE", WITH ALL FAULTS AND
#    WITHOUT WARRANTY OF ANY KIND, AND THE AUTHOR OF THIS SHELL SCRIPT'S LICENSORS
#    (COLLECTIVELY REFERRED TO AS "THE AUTHOR" FOR THE PURPOSES OF THIS DISCLAIMER)
#    HEREBY DISCLAIM ALL WARRANTIES AND CONDITIONS WITH RESPECT TO THIS SHELL SCRIPT
#    SOFTWARE AND SERVICES, EITHER EXPRESS, IMPLIED OR STATUTORY, INCLUDING, BUT
#    NOT LIMITED TO, THE IMPLIED WARRANTIES AND/OR CONDITIONS OF
#    MERCHANTABILITY, SATISFACTORY QUALITY, FITNESS FOR A PARTICULAR PURPOSE,
#    ACCURACY, QUIET ENJOYMENT, AND NON-INFRINGEMENT OF THIRD PARTY RIGHTS.
#
# C. THE AUTHOR DOES NOT WARRANT AGAINST INTERFERENCE WITH YOUR ENJOYMENT OF THE
#    THE AUTHOR's SOFTWARE AND SERVICES, THAT THE FUNCTIONS CONTAINED IN, OR
#    SERVICES PERFORMED OR PROVIDED BY, THIS SHELL SCRIPT WILL MEET YOUR
#    REQUIREMENTS, THAT THE OPERATION OF THIS SHELL SCRIPT OR SERVICES WILL
#    BE UNINTERRUPTED OR ERROR-FREE, THAT ANY SERVICES WILL CONTINUE TO BE MADE
#    AVAILABLE, THAT THIS SHELL SCRIPT OR SERVICES WILL BE COMPATIBLE OR
#    WORK WITH ANY THIRD PARTY SOFTWARE, APPLICATIONS OR THIRD PARTY SERVICES,
#    OR THAT DEFECTS IN THIS SHELL SCRIPT OR SERVICES WILL BE CORRECTED.
#    INSTALLATION OF THIS THE AUTHOR SOFTWARE MAY AFFECT THE USABILITY OF THIRD
#    PARTY SOFTWARE, APPLICATIONS OR THIRD PARTY SERVICES.
#
# D. YOU FURTHER ACKNOWLEDGE THAT THIS SHELL SCRIPT AND SERVICES ARE NOT
#    INTENDED OR SUITABLE FOR USE IN SITUATIONS OR ENVIRONMENTS WHERE THE FAILURE
#    OR TIME DELAYS OF, OR ERRORS OR INACCURACIES IN, THE CONTENT, DATA OR
#    INFORMATION PROVIDED BY THIS SHELL SCRIPT OR SERVICES COULD LEAD TO
#    DEATH, PERSONAL INJURY, OR SEVERE PHYSICAL OR ENVIRONMENTAL DAMAGE,
#    INCLUDING WITHOUT LIMITATION THE OPERATION OF NUCLEAR FACILITIES, AIRCRAFT
#    NAVIGATION OR COMMUNICATION SYSTEMS, AIR TRAFFIC CONTROL, LIFE SUPPORT OR
#    WEAPONS SYSTEMS.
#
# E. NO ORAL OR WRITTEN INFORMATION OR ADVICE GIVEN BY THE AUTHOR
#    SHALL CREATE A WARRANTY. SHOULD THIS SHELL SCRIPT OR SERVICES PROVE DEFECTIVE,
#    YOU ASSUME THE ENTIRE COST OF ALL NECESSARY SERVICING, REPAIR OR CORRECTION.
#
#    Limitation of Liability.
# F. TO THE EXTENT NOT PROHIBITED BY APPLICABLE LAW, IN NO EVENT SHALL THE AUTHOR
#    BE LIABLE FOR PERSONAL INJURY, OR ANY INCIDENTAL, SPECIAL, INDIRECT OR
#    CONSEQUENTIAL DAMAGES WHATSOEVER, INCLUDING, WITHOUT LIMITATION, DAMAGES
#    FOR LOSS OF PROFITS, CORRUPTION OR LOSS OF DATA, FAILURE TO TRANSMIT OR
#    RECEIVE ANY DATA OR INFORMATION, BUSINESS INTERRUPTION OR ANY OTHER
#    COMMERCIAL DAMAGES OR LOSSES, ARISING OUT OF OR RELATED TO YOUR USE OR
#    INABILITY TO USE THIS SHELL SCRIPT OR SERVICES OR ANY THIRD PARTY
#    SOFTWARE OR APPLICATIONS IN CONJUNCTION WITH THIS SHELL SCRIPT OR
#    SERVICES, HOWEVER CAUSED, REGARDLESS OF THE THEORY OF LIABILITY (CONTRACT,
#    TORT OR OTHERWISE) AND EVEN IF THE AUTHOR HAS BEEN ADVISED OF THE
#    POSSIBILITY OF SUCH DAMAGES. SOME JURISDICTIONS DO NOT ALLOW THE EXCLUSION
#    OR LIMITATION OF LIABILITY FOR PERSONAL INJURY, OR OF INCIDENTAL OR
#    CONSEQUENTIAL DAMAGES, SO THIS LIMITATION MAY NOT APPLY TO YOU. In no event
#    shall THE AUTHOR's total liability to you for all damages (other than as may
#    be required by applicable law in cases involving personal injury) exceed
#    the amount of five dollars ($5.00). The foregoing limitations will apply
#    even if the above stated remedy fails of its essential purpose.
################################################################################

import hashlib
import os
import argparse
import subprocess
import json
import platform
import sarif_om as sarif
import datetime
from typing import Dict, List, Optional
from urllib.parse import quote
import flake8

class Flake8LintCLI:
	SARIF_SCHEMA_URL = str(
		"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/refs/heads/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
	)

	FLAKE8_VERSION_STR = flk8_ver = f"{flake8.__version_info__[0]}.{flake8.__version_info__[1]}.{flake8.__version_info__[2]}"

	SAFE_ENV_VARS = [
		"PATH", "HOME", "USER", "SHELL", "LANG", "PWD",
		"EDITOR", "TERM", "LOGNAME", "XDG_CURRENT_DESKTOP",
		"XDG_SESSION_TYPE", "XDG_SESSION_DESKTOP", "XDG_RUNTIME_DIR",
		"HOSTNAME", "SHLVL", "PYTHONCOERCECLOCALE", "PYTHONUTF8",
		"PYTHONHOME", "PYTHONPATH", "PYTHONSAFEPATH", "PYTHONPLATLIBDIR",
		"PYTHONSTARTUP", "PYTHONOPTIMIZE", "PYTHONBREAKPOINT", "PYTHONDEBUG",
		"PYTHONINSPECT", "PYTHONUNBUFFERED", "PYTHONVERBOSE", "PYTHONCASEOK",
		"PYTHONDONTWRITEBYTECODE", "PYTHONPYCACHEPREFIX", "PYTHONINTMAXSTRDIGITS",
		"PYTHONIOENCODING", "PYTHONNOUSERSITE", "PYTHONUSERBASE", "PYTHONEXECUTABLE",
		"PYTHONWARNINGS", "PYTHONFAULTHANDLER", "PYTHONTRACEMALLOC", "PYTHONPROFILEIMPORTTIME",
		"PYTHONASYNCIODEBUG", "PYTHONMALLOC", "PYTHONMALLOCSTATS", "PYTHONLEGACYWINDOWSFSENCODING",
		"PYTHONLEGACYWINDOWSSTDIO", "PYTHONDEVMODE", "PYTHONWARNDEFAULTENCODING",
		"PYTHONNODEBUGRANGES", "PYTHONPERFSUPPORT", "PYTHON_PERF_JIT_SUPPORT", "PYTHON_CPU_COUNT",
		"PYTHON_FROZEN_MODULES", "PYTHON_COLORS", "PYTHON_BASIC_REPL", "PYTHON_HISTORY",
		"PYTHON_GIL", "PYTHON_PRESITE", "PYTHONDUMPREFSFILE", "PYTHONDUMPREFS"
	]

	def __init__(self, config, files: List[str]):
		# self.severity = severity
		self.files = files
		self.config = config if config else None
		self.rule_docs_cache: Dict[str, str] = {}
		self.command = None
		self.start_time = None
		self.end_time = None
		self.execution_successful = False

	def run_flake8(self):
		"""Run flake8 with the specified arguments and return the JSON output."""
		self.command = [
			"flake8",
			f"--append-config={self.config}" if self.config else "--extend-select E,W",
			"--format=json",
			"--max-line-length=100",
			"--exit-zero"
		] + self.files
		try:
			self.start_time = str(datetime.datetime.now(datetime.UTC))
			result = subprocess.run(self.command, capture_output=True, text=True, check=True)
			self.execution_successful = True
			self.end_time = str(datetime.datetime.now(datetime.UTC))
			return json.loads(result.stdout)
		except subprocess.CalledProcessError as e:
			self.execution_successful = False
			self.end_time = str(datetime.datetime.now(datetime.UTC))
			print(f"::warning file={__file__},title='Error running flake8':: {e}")
			if e.stderr:
				print(f"::warning file=flake8,title='Error from flake8':: {e.stderr}")
				print("")
			return json.loads(e.stdout)

	def validate_position(self, value: Optional[int], default: int = 1) -> int:
		"""Validate and convert position values."""
		try:
			val = int(value) if value is not None else default
			return max(val, default)
		except (TypeError, ValueError):
			return default

	def create_region(self, entry: dict) -> sarif.Region:
		"""Create a valid SARIF region object."""
		return sarif.Region(
			start_line=self.validate_position(entry.get('line')),
			start_column=self.validate_position(entry.get('column')),
			end_line=self.validate_position(entry.get('endLine')),
			end_column=self.validate_position(entry.get('endColumn')),
			char_length=(self.validate_position(entry.get('endColumn')) - self.validate_position(entry.get('column'))) if (self.validate_position(entry.get('line')) == self.validate_position(entry.get('endLine'))) else None
		)

	def create_fix(self, file: str, fix_data: dict) -> Optional[sarif.Fix]:
		"""Create a SARIF Fix object from flake8 fix data."""
		if not fix_data or not fix_data.get('replacements'):
			return None
		
		replacements = []
		for repl in fix_data.get('replacements', []):
			if not repl.get('replacement'):
				continue
			
			region = self.create_region(fix_data)
			
			replacements.append(
				sarif.Replacement(
					deleted_region=region,
					inserted_content=sarif.ArtifactContent(
						text=repl.get('replacement', '')
					)
				)
			)
		
		if not replacements:
			return None
			
		return sarif.Fix(
			description=sarif.Message(
				text=fix_data.get('replacements', [{}])[0].get('replacement', '')
			),
			artifact_changes=[
				sarif.ArtifactChange(
					artifact_location=sarif.ArtifactLocation(
						index=0,
						uri=fix_data.get('file', '') if fix_data.get('file', '') else file
					),
					replacements=replacements
				)
			]
		)

	def create_id(self, file: str) -> int:
		"""Create a unique ID for a location that fits within int32 range."""
		# Create a SHA-256 hash object
		sha256_hash = hashlib.sha256()
		# Update the hash object with the normalized path encoded to bytes
		sha256_hash.update(file.encode('utf-8'))
		# Get first 4 bytes of the hash and convert to int
		# This ensures the ID is always within int32 range (0 to 2^31-1)
		id_bytes = sha256_hash.digest()[:4]
		id_value = int.from_bytes(id_bytes, byteorder='big') & 0x7fffffff
		return id_value

	def compact_json_output(self, data):
		# Convert the data to a compact JSON string
		return json.dumps(data, indent=None, separators=(',', ':'), sort_keys=True)

	def generate_weak_fingerprint(self, data):
		"""Generate a unstable fingerprint from the provided data."""
		# Remove any None values and normalize the data structure
		cleaned_data = self.remove_none_values(data)
		# Convert to a stable string representation
		data_string = self.compact_json_output(cleaned_data)
		# Create a SHA-256 hash of the data string
		return hashlib.sha1(data_string.encode('utf-8')).hexdigest()

	def generate_partial_weak_fingerprint(self, rule_id, message):
		"""Generate a partial fingerprint from rule ID and message."""
		partial_data = {
			"ruleId": rule_id.strip() if rule_id else "",
			"message": message.get("text", "").strip()
		}
		return self.generate_weak_fingerprint(partial_data)

	def generate_fingerprint(self, data):
		"""Generate a stable fingerprint from the provided data."""
		# Remove any None values and normalize the data structure
		cleaned_data = self.remove_none_values(data)
		# Convert to a stable string representation
		data_string = self.compact_json_output(cleaned_data)
		# Create a SHA-256 hash of the data string
		return hashlib.sha256(data_string.encode('utf-8')).hexdigest()

	def generate_partial_fingerprint(self, rule_id, message):
		"""Generate a partial fingerprint from rule ID and message."""
		partial_data = {
			"ruleId": rule_id.strip() if rule_id else "",
			"message": message.get("text", "").strip()
		}
		return self.generate_fingerprint(partial_data)

	def grade_code(self, code: str) -> str:
		"""Yields the kind of result from the given code."""
		if not code:
			return "notApplicable"
		elif ("W" in code.upper()) or ("E" in code.upper()):
			return "fail"
		elif ("D" in code.upper()) or ("C" in code.upper()) or ("B" in code.upper()):
			return "review"
		else:
			return "informational"

	def triage_code(self, code: str) -> str:
		"Yields the severity of the given code."
		if not code:
			return "none"
		elif ("S" in code.upper()) or ("E" in code.upper()):
			return "error"
		elif ("W" in code.upper()) or ("C" in code.upper()) or ("B" in code.upper()):
			return "warning"
		elif ("D" in code.upper()) or ("N" in code.upper()) or ("F" in code.upper()):
			return "note"
		else:
			return "none"

	def convert_to_sarif(self, flake8_results):
		"""Convert flake8 JSON results to SARIF format using sarif-om."""
		sarif_log = sarif.SarifLog(
			version="2.1.0",
			runs=[
				sarif.Run(
					tool=sarif.Tool(
						driver=sarif.ToolComponent(
							name="flake8",
							version=self.FLAKE8_VERSION_STR,  # Update to your flake8 version
							information_uri="https://flake8.pycqa.org/",
							rules=[]
						)
					),
					artifacts=[],
					results=[],
					invocations=[self.create_invocation()],
					default_source_language="python"
				)
			]
		)

		run = sarif_log.runs[0]
		driver = run.tool.driver
		rule_ids = {}

		for file_uri, violations in flake8_results.items():
			if file_uri not in [artifact.location.uri for artifact in run.artifacts]:
					run.artifacts.append(sarif.Artifact(
						roles=["analysisTarget", "referencedOnCommandLine"],
						location=sarif.ArtifactLocation(index=len(run.artifacts), uri=file_uri),
						source_language="python"
					))
			for entry in violations:
				code = entry.get('code', '')

				if code not in rule_ids:
					rule = sarif.ReportingDescriptor(
						id=code,
						name=code,
						short_description=sarif.MultiformatMessageString(
							text=entry.get('text', '')
						),
						full_description=sarif.MultiformatMessageString(
							text=entry.get('text', '')
						),
						# MIT code-listing for now
						help_uri=f"https://flakes.orsinium.dev/#{code}",
						help=sarif.MultiformatMessageString(
							text=entry.get('text', '')
						)
					)
					driver.rules.append(rule)
					rule_ids[code] = rule

				result = sarif.Result(
					rule_id=code,
					rule_index=next((i for i, deRule in enumerate(driver.rules) if deRule == rule), None),
					message=sarif.Message(
						text=entry.get('text', '')
					),
					kind=self.grade_code(code),
					severity=self.triage_code(code),
					locations=[
						sarif.Location(
							id=self.create_id(file_uri),
							physical_location=sarif.PhysicalLocation(
								artifact_location=sarif.ArtifactLocation(
									index=0,
									uri=file_uri
								),
								region=self.create_region(entry)
							)
						)
					]
				)

				run.results.append(result)

		return sarif_log

	def remove_none_values(self, d):
		"""Recursively remove keys with None values from a dictionary."""
		if isinstance(d, dict):
			return {k: self.remove_none_values(v) for k, v in d.items() if v is not None}
		elif isinstance(d, list):
			return [self.remove_none_values(i) for i in d if i is not None]
		return d

	def toCamelCase(self, snake_str):
		components = snake_str.split('_')
		return components[0] + ''.join(x.title() for x in components[1:])

	def convert_dict_keysToCamelCase(self, input_dict):
		if isinstance(input_dict, dict):
			int_list = [
				"startLine", "endLine", "startColumn", "endColumn", "byteOffset",
				"charOffset", "length", "parentIndex"
			]
			# "ruleIndex", "rank", "index"
			newDict = {}
			for key, value in input_dict.items():
				newKey = self.toCamelCase(key)
				# Check if the key is in the specified list and the value is not positive
				if newKey in int_list and (value < 1):
					continue  # Skip this key-value pair
				new_value = self.convert_dict_keysToCamelCase(value)  # Recursively convert values
				newDict[newKey] = new_value
			return newDict
		elif isinstance(input_dict, list):
			return [self.convert_dict_keysToCamelCase(item) for item in input_dict]  # Handle lists
		else:
			return input_dict  # Return the value if it's not a dictionary

	def add_fingerprints_to_sarif(self, sarif_data):
		"""Add fingerprints to SARIF results following the SARIF 2.1.0 specification."""
		# Iterate over each run in the SARIF data
		for run in sarif_data.get("runs", []):
			# Iterate over each result in the current run
			for result in run.get("results", []):
				# Check if there is at least one location
				locations = result.get("locations")
				if locations and len(locations) > 0:
					# Create a dictionary with relevant fields for fingerprint generation
					finding_data = {
						"ruleId": result.get("ruleId", "").strip(),
						"message": result.get("message", {}).get("text", "").strip(),
						"location": locations[0]
					}
					# Generate fingerprints as key-value pairs
					result["fingerprints"] = {
						"SHA256": self.generate_fingerprint(finding_data),
						"SHA1": self.generate_weak_fingerprint(finding_data)
					}
					# Generate partial fingerprints as key-value pairs
					result["partialFingerprints"] = {
						"ruleMessageFingerprint/SHA256": self.generate_partial_fingerprint(
							result.get("ruleId", ""),
							result.get("message", {})
						),
						"ruleMessageFingerprint/SHA1": self.generate_partial_weak_fingerprint(
							result.get("ruleId", ""),
							result.get("message", {})
						)
					}
		return sarif_data

	def create_invocation(self) -> sarif.Invocation:
		"""Create a SARIF invocation object with details of the flake8 run."""
		safe_env_vars = {key: os.environ[key] for key in self.SAFE_ENV_VARS if key in os.environ}
		cli_args = []
		for nextFile in self.files:
			cli_args.append(str(os.path.normpath(nextFile)))
		return sarif.Invocation(
			command_line=" ".join([tok for tok in self.command if tok not in self.files]),
			arguments=cli_args,
			start_time_utc=self.start_time,
			end_time_utc=self.end_time,
			execution_successful=self.execution_successful,
			working_directory=sarif.ArtifactLocation(index=0, uri=os.getcwd()),
			machine=platform.node(),
			account=platform.node(),
			environment_variables=safe_env_vars
		)

	def write_sarif(self, file: str, sarif_log: sarif.SarifLog):
		"""Write the SARIF log to a file."""
		if not file:
			file = "flake8.sarif"
		with open(file, "w") as sarif_file:
			try:
				# Convert to dict and add schema
				sarif_dict = json.loads(json.dumps(sarif_log, default=lambda o: o.__dict__))
				sarif_dict["$schema"] = self.SARIF_SCHEMA_URL
				
				# Clean up the dictionary
				sarif_dict = self.remove_none_values(self.convert_dict_keysToCamelCase(sarif_dict))
				sarif_dict = self.add_fingerprints_to_sarif(sarif_dict)
				
				# Write to file
				json.dump(sarif_dict, sarif_file, indent=2)
			except Exception as e:
				print(f"::error file={__file__},title='Error serializing {file}':: {e}")
				raise RuntimeError(f"Could not produce output JSON: {e}") from e


def main():
	parser = argparse.ArgumentParser(description="Run flake8 and output results in SARIF format.")
	parser.add_argument("--output", default="flake8.sarif",
		help="Specify the output SARIF file name.")
	parser.add_argument("--config", required=False, default="**/.flake8.ini",
		help="Specify the Flake8 config file name.")
	parser.add_argument("FILES", nargs='+', help="One or more files or glob patterns to check.")

	args = parser.parse_args()

	cli_tool = Flake8LintCLI(args.config if args.config else None, files=args.FILES)
	flake8_results = cli_tool.run_flake8()
	sarif_log = cli_tool.convert_to_sarif(flake8_results)
	try:
		cli_tool.write_sarif(args.output, sarif_log)
	except Exception as e:
		print(f"::error file={__file__},title='Error while serializing results':: {e}")

if __name__ == "__main__":
	main()
