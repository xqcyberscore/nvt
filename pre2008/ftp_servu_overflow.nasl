# OpenVAS Vulnerability Test
# Description: Serv-U FTP Server SITE CHMOD Command Stack Overflow Vulnerability
#
# Authors:
# Astharot <astharot@zone-h.org>
#
# Copyright:
# Copyright (C) 2004 Astharot
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

CPE = "cpe:/a:serv-u:serv-u";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12037");
  script_version("2019-06-24T07:41:01+0000");
  script_tag(name:"last_modification", value:"2019-06-24 07:41:01 +0000 (Mon, 24 Jun 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-2111", "CVE-2004-2533");
  script_bugtraq_id(9483, 9675);
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");

  script_name("Serv-U FTP Server SITE CHMOD Command Stack Overflow Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("FTP");
  script_copyright("This script is Copyright (C) 2004 Astharot");
  script_dependencies("gb_solarwinds_serv-u_consolidation.nasl");
  script_mandatory_keys("solarwinds/servu/detected");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to Serv-U FTP Server version 4.2 or later.");

  script_tag(name:"summary", value:"The remote host is running Serv-U FTP server.

  There is a bug in the way this server handles arguments to the SITE CHMOD requests.");

  script_tag(name:"impact", value:"This flaw may allow an attacker to trigger a buffer overflow against
  this server, which may allow him to disable this server remotely or to execute arbitrary code on this host.");

  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2004-01/0249.html");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/fulldisclosure/2004-02/0881.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "4.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
