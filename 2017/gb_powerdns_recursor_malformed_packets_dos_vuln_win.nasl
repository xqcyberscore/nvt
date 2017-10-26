###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_powerdns_recursor_malformed_packets_dos_vuln_win.nasl 7543 2017-10-24 11:02:02Z cfischer $
#
# PowerDNS Recursor Specific Sequence Denial of Service Vulnerability (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:powerdns:recursor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807393");
  script_version("$Revision: 7543 $");
  script_cve_id("CVE-2014-3614");
  script_bugtraq_id(69778);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-10-24 13:02:02 +0200 (Tue, 24 Oct 2017) $");
  script_tag(name:"creation_date", value:"2017-01-17 13:50:29 +0530 (Tue, 17 Jan 2017)");
  script_name("PowerDNS Recursor Specific Sequence Denial of Service Vulnerability (Windows)");
  
  script_tag(name:"summary", value:"This host is running PowerDNS Recursor
  and is prone to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw exists due to an error in the 
  handling a specific sequence of packets which leads to  crash PowerDNS
  Recursor remotely.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause the target service to crash.

  Impact Level: Application");

  script_tag(name:"affected", value:"PowerDNS Recursor 3.6.0 on Windows.");

  script_tag(name:"solution", value:"Upgrade to PowerDNS Recursor 3.6.1 or later,
  For updates refer to https://doc.powerdns.com/md");

  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2014/q3/589");
  script_xref(name:"URL", value:"https://blog.powerdns.com/2014/09/10/security-update-powerdns-recursor-3-6-1");
  script_xref(name:"URL", value:"http://doc.powerdns.com/html/changelog.html");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("pdns_version.nasl", "os_detection.nasl");
  script_mandatory_keys("powerdns/recursor/installed", "Host/runs_windows");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

# Get Port
if(!dnsPort = get_app_port(cpe:CPE)){
 exit(0);
}

## Get Version
if(!infos = get_app_version_and_proto(cpe:CPE, port:dnsPort)){
  exit(0);
}

version = infos["version"];
proto = infos["proto"];

## Check for vulnerable version
if(version_is_equal(version: version, test_version: "3.6.0"))
{
  fix = "3.6.1";
  report = report_fixed_ver(installed_version:version, fixed_version:fix);
  security_message(data:report, port:dnsPort, proto:proto);
  exit(0);
}
