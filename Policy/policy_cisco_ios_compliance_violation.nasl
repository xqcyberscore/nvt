##############################################################################
# OpenVAS Vulnerability Test
# $Id: policy_cisco_ios_compliance_violation.nasl 4982 2017-01-11 08:57:53Z ckuerste $
#
# Cisco IOS Compliance Check: Failed
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106433");
  script_version("$Revision: 4982 $");
  script_tag(name: "last_modification", value: "$Date: 2017-01-11 09:57:53 +0100 (Wed, 11 Jan 2017) $");
  script_tag(name: "creation_date", value: "2017-01-11 10:55:08 +0700 (Wed, 11 Jan 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name: "qod", value: "98");

  script_name("Cisco IOS Compliance Check: Failed");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("policy_cisco_ios_compliance.nasl");
  script_mandatory_keys("policy/cisco_ios_compliance/failed");

  script_tag(name: "summary", value: "Lists all the Cisco IOS Compliance Policy Checks which did NOT pass.");

  exit(0);
}

failed = get_kb_item("policy/cisco_ios_compliance/failed");

if (failed) {
  failed = split(failed, keep: FALSE);

  report = max_index(failed) + " Checks failed:\n\n";

  foreach line (failed) {
    entry = split(line, sep: "||", keep: FALSE);
    report += "Titel:       " + entry[0] + "\n";
    report += "Description: " + entry[1] + "\n";
    report += "Solution:    " + entry[2] + "\n";
    if (max_index(entry) == 4)
      report += "Remediation: " + entry[3] + "\n";
    report += '\n';
  }

  log_message(data: report, port: 0, proto: "ssh");
}

exit(0);
