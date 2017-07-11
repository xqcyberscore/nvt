###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sonatype_nexus_bypass_vuln.nasl 6214 2017-05-26 09:04:01Z teissa $
#
# Sonatype Nexus OSS/Pro Security Bypass Vulnerability
#
# Authors:
# Deependra Bapna <bdeependra@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:sonatype:nexus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805330");
  script_version("$Revision: 6214 $");
  script_cve_id("CVE-2014-2034");
  script_bugtraq_id(65956);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-05-26 11:04:01 +0200 (Fri, 26 May 2017) $");
  script_tag(name:"creation_date", value:"2015-01-27 13:00:12 +0530 (Tue, 27 Jan 2015)");
  script_name("Sonatype Nexus OSS/Pro Security Bypass Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Nexus OSS/Pro
  and is prone to security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version of Nexus OSS/Pro
  with the help of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"Certain unspecified input is not properly
  verified before being used to read files.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to bypass certain security restrictions.

  Impact Level: Application");

  script_tag(name:"affected", value:"Nexus OSS/Pro versions 2.4.0 through 2.7.1.");

  script_tag(name:"solution", value:"Upgrade to Nexus OSS/Pro version 2.7.2 or
  later. For updates refer http://www.sonatype.org.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/57142");
  script_xref(name : "URL" , value : "http://www.sonatype.org/advisories/archive/2014-03-03-Nexus");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_sonatype_nexus_detect.nasl");
  script_mandatory_keys("nexus/installed");
  script_require_ports("Services/www", 8081);
  exit(0);
}

##Code starts from here##

include("host_details.inc");
include("version_func.inc");

## Variable Initialization
http_port = "";
nexusVer= "";

## Get HTTP Port
if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

# Get Version
if(!nexusVer = get_app_version(cpe:CPE, port:http_port)){
  exit(0);
}

if(version_in_range(version:nexusVer, test_version:"2.4.0", test_version2:"2.7.1"))
{
  report = 'Installed version: ' + nexusVer + '\n' +
           'Fixed version: 2.7.2\n';

  security_message(port:http_port, data:report);
  exit(0);
}
