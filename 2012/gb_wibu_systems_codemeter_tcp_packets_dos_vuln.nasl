###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wibu_systems_codemeter_tcp_packets_dos_vuln.nasl 6022 2017-04-25 12:51:04Z teissa $
#
# Wibu-Systems CodeMeter RunTime TCP Packets Denial of Service Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:wibu:codemeter_webadmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802382");
  script_version("$Revision: 6022 $");
  script_cve_id("CVE-2011-4057");
  script_bugtraq_id(51382);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-04-25 14:51:04 +0200 (Tue, 25 Apr 2017) $");
  script_tag(name:"creation_date", value:"2012-01-19 15:06:52 +0530 (Thu, 19 Jan 2012)");
  script_name("Wibu-Systems CodeMeter Runtime TCP Packets Denial of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_codemeter_webadmin_detect.nasl");
  script_mandatory_keys("CodeMeter_WebAdmin/installed");
  script_require_ports("Services/www", 22350);

  script_xref(name:"URL", value:"http://secunia.com/advisories/47497");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/659515");
  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN78901873/index.html");
  script_xref(name:"URL", value:"http://jvndb.jvn.jp/en/contents/2012/JVNDB-2012-000003.html");

  tag_impact = "Successful exploitation will let attackers to cause a denial of service condition.

  Impact Level: Application";

  tag_affected = "Wibu-Systems CodeMeter version before 4.40";

  tag_insight = "The flaw is due to an unspecified error which fails to handle
  crafted packets to TCP port 22350.";

  tag_solution = "Upgrade to Wibu-Systems CodeMeter version 4.40 or later
  For updates refer to  http://www.wibu.com/en/home.html";

  tag_summary = "The host is running Wibu-Systems CodeMeter Runtime and is prone to denial of service
  vulnerability.";

  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected", value:tag_affected);
  script_tag(name:"insight", value:tag_insight);
  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

## Check for CodeMeter Version prior to 4.40
if( version_is_less( version:vers, test_version:"4.40" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"4.40" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
