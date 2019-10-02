# Copyright (C) 2018 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

CPE = "cpe:/a:openbsd:openssh";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813887");
  script_version("2019-09-26T09:12:46+0000");
  script_cve_id("CVE-2018-15919");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-09-26 09:12:46 +0000 (Thu, 26 Sep 2019)");
  script_tag(name:"creation_date", value:"2018-09-05 13:12:09 +0530 (Wed, 05 Sep 2018)");
  script_name("OpenSSH 'auth2-gss.c' User Enumeration Vulnerability (Windows)");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_openssh_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssh/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"https://bugzilla.novell.com/show_bug.cgi?id=1106163");
  script_xref(name:"URL", value:"https://seclists.org/oss-sec/2018/q3/180");

  script_tag(name:"summary", value:"This host is installed with openssh and
  is prone to user enumeration vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists in the 'auth-gss2.c' source
  code file of the affected software and is due to insufficient validation of
  an authentication request packet when the Guide Star Server II (GSS2) component
  is used on an affected system.");

  script_tag(name:"impact", value:"Successfully exploitation will allow remote
  attacker to harvest valid user accounts, which may aid in brute-force attacks.");

  script_tag(name:"affected", value:"OpenSSH version 5.9 to 7.8 on Windows.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("revisions-lib.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if((revcomp(a:vers, b:"7.8p1") <= 0) && (revcomp(a:vers, b:"5.9") >= 0)) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"None", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
