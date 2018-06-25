###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_tika_server_xxe_vuln.nasl 10299 2018-06-22 11:50:53Z santu $
#
# Apache Tika Server XXE Vulnerability
#
# Authors:
# Rajat Mishra <rajatm@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:apache:tika";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813535");
  script_version("$Revision: 10299 $");
  script_cve_id("CVE-2016-4434");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-06-22 13:50:53 +0200 (Fri, 22 Jun 2018) $");
  script_tag(name:"creation_date", value:"2018-06-20 15:31:31 +0530 (Wed, 20 Jun 2018)");
  script_name("Apache Tika Server XXE Vulnerability");

  script_tag(name:"summary", value:"The host is installed with Apache Tika Server
  and is prone to an XML External Entity (XXE) vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help of
  detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw exists due to Apache Tika failing to
  initialize the XML parser or choose handlers properly.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct XML External Entity (XXE) attacks via vectors involving
  spreadsheets in OOXML files and XMP metadata in PDF and other file formats.

  Impact Level: Application");

  script_tag(name:"affected", value:"Apache Tika Server 0.10 to 1.12");

  script_tag(name:"solution", value:"Upgrade to Apache Tika Server 1.13 or later.
  For updates refer to Reference links.");
 
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name : "URL" , value : "https://mail-archives.apache.org/mod_mbox/tika-dev/201605.mbox/%3C1705136517.1175366.1464278135251.JavaMail.yahoo%40mail.yahoo.com%3E");
  script_xref(name : "URL" , value : "https://tika.apache.org");
  
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_apache_tika_server_detect.nasl");
  script_mandatory_keys("Apache/Tika/Server/Installed");
  script_require_ports("Services/www", 9998, 80);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!tPort = get_app_port(cpe:CPE)){
  exit(0);
}

infos = get_app_version_and_location(cpe:CPE, port:tPort, exit_no_version:TRUE);
tVer = infos['version'];
tPath = infos['location'];

if(version_in_range(version:tVer, test_version:"0.10", test_version2:"1.12"))
{
  report = report_fixed_ver(installed_version:tVer, fixed_version:"1.13", install_path:tPath);
  security_message(data:report, port:tPort);
  exit(0); 
}  
exit(0);
