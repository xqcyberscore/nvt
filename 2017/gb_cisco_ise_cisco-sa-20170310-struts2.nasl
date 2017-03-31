###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ise_cisco-sa-20170310-struts2.nasl 5575 2017-03-15 06:07:53Z ckuerste $
#
# Cisco Identity Services Engine Apache Struts2 Jakarta Multipart Parser File Upload Code Execution Vulnerability
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
# of the License, or (at your option) any later version.
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

CPE = "cpe:/a:cisco:identity_services_engine";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.106640");
 script_cve_id("CVE-2017-5638");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_version ("$Revision: 5575 $");

 script_name("Cisco Identity Services Engine Apache Struts2 Jakarta Multipart Parser File Upload Code Execution Vulnerability");

 script_xref(name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170310-struts2");

 script_tag(name: "vuldetect", value: "Check the version.");

 script_tag(name: "solution", value: "No solution or patch is available as of 14th March, 2017. Information
regarding this issue will be updated once the solution details are available.");

 script_tag(name: "summary", value: "Cisco ISE is prone to a vulnerability in Apache Struts2.");

 script_tag(name: "insight", value: "On March 6, 2017, Apache disclosed a vulnerability in the Jakarta multipart
parser used in Apache Struts2 that could allow an attacker to execute commands remotely on the targeted system
using a crafted Content-Type header value.");

 script_tag(name: "qod_type", value: "package");
 script_tag(name: "solution_type", value: "NoneAvailable");

 script_tag(name: "last_modification", value: "$Date: 2017-03-15 07:07:53 +0100 (Wed, 15 Mar 2017) $");
 script_tag(name: "creation_date", value: "2017-03-13 11:35:28 +0700 (Mon, 13 Mar 2017)");
 script_category(ACT_GATHER_INFO);
 script_family("CISCO");
 script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
 script_dependencies("gb_cisco_ise_version.nasl");
 script_mandatory_keys("cisco_ise/version");

 exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE))
  exit(0);

affected = make_list('1.3.0.876',
                     '1.4.0.253',
                     '2.0.0.306',
                     '2.2.0.470',
                     '2.0.1.130',
                     '2.2.0.471');

foreach af (affected) {
  if (version == af) {
    report = report_fixed_ver(installed_version: version, fixed_version: "None");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);

