###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_b2evolution_file_upload_vuln.nasl 6836 2017-08-02 14:05:29Z asteins $
#
# b2evolution File Upload Vulnerability
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

CPE = "cpe:/a:b2evolution:b2evolution";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106669");
  script_version("$Revision: 6836 $");
  script_tag(name: "last_modification", value: "$Date: 2017-08-02 16:05:29 +0200 (Wed, 02 Aug 2017) $");
  script_tag(name: "creation_date", value: "2017-03-17 15:44:20 +0700 (Fri, 17 Mar 2017)");
  script_tag(name: "cvss_base", value: "6.5");
  script_tag(name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_tag(name: "qod_type", value: "remote_banner");

  script_tag(name: "solution_type", value: "WillNotFix");

  script_name("b2evolution File Upload Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_b2evolution_detect.nasl");
  script_mandatory_keys("b2evolution/installed");

  script_tag(name: "summary", value: "b2evolution is prone to a unrestricted file upload vulnerability.");

  script_tag(name: "vuldetect", value: "Checks the version.");

  script_tag(name: "insight", value: "Unrestricted file upload vulnerability in 'file upload' modules in
b2evolution CMS allows authenticated user to upload malicious code (shell), even though in the system has
restricted extension (php).");

  script_tag(name: "affected", value: "b2evolution 6.8.8.");

  script_tag(name: "solution", value: "This issue is no longer subject to a fix and therefore does not need a solution.");

  script_xref(name: "URL", value: "https://rungga.blogspot.co.id/2017/03/remote-file-upload-vulnerability-in.html");

## Deprecated since CVE-2017-6902 has been REJECTED
  script_tag(name: "deprecated", value: TRUE);

  exit(0);
}

exit(66);

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_equal(version: version, test_version: "6.8.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
