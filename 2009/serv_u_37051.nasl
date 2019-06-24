###############################################################################
# OpenVAS Vulnerability Test
#
# RhinoSoft Serv-U FTP Server TEA Decoder Remote Stack Buffer Overflow Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

CPE = "cpe:/a:serv-u:serv-u";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100354");
  script_version("2019-06-24T07:41:01+0000");
  script_tag(name:"last_modification", value:"2019-06-24 07:41:01 +0000 (Mon, 24 Jun 2019)");
  script_tag(name:"creation_date", value:"2009-11-19 19:04:52 +0100 (Thu, 19 Nov 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-4006");
  script_bugtraq_id(37051);

  script_name("RhinoSoft Serv-U FTP Server TEA Decoder Remote Stack Buffer Overflow Vulnerability");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("FTP");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("gb_solarwinds_serv-u_consolidation.nasl");
  script_mandatory_keys("solarwinds/servu/detected");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");

  script_tag(name:"summary", value:"RhinoSoft Serv-U FTP Server is prone to a remote stack-based buffer-
  overflow vulnerability because the application fails to perform adequate boundary checks on user-supplied data.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to execute arbitrary code within the
  context of the affected application. Failed exploit attempts will result in a denial-of-service condition.");

  script_tag(name:"affected", value:"Serv-U 9.0.0.5 is vulnerable. Other versions may also be affected.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37051");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/507955");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "9.1.0.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.1.0.0");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
