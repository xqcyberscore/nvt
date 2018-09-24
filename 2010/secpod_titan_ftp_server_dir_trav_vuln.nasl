##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_titan_ftp_server_dir_trav_vuln.nasl 11575 2018-09-24 14:25:50Z cfischer $
#
# Titan FTP Server 'XCRC' and 'COMB' Directory Traversal Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902087");
  script_version("$Revision: 11575 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-24 16:25:50 +0200 (Mon, 24 Sep 2018) $");
  script_tag(name:"creation_date", value:"2010-07-02 08:02:13 +0200 (Fri, 02 Jul 2010)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_cve_id("CVE-2010-2425", "CVE-2010-2426");
  script_bugtraq_id(40949, 40904);
  script_name("Titan FTP Server 'XCRC' and 'COMB' Directory Traversal Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/40237");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/59492");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/511839/100/0/threaded");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("gb_titan_ftp_detect.nasl");
  script_mandatory_keys("TitanFTP/Server/Ver");

  script_tag(name:"insight", value:"The flaws are due to

  - Input validation error when processing 'XCRC' commands, which can be
  exploited to determine the existence of a file outside the FTP root directory.

  - Input validation error when processing 'COMB' commands, which can be
  exploited to read and delete an arbitrary file.");

  script_tag(name:"solution", value:"Upgrade to Titan FTP Server 8.30.1231 or later
  For updates refer to http://www.titanftp.com/index.html");

  script_tag(name:"summary", value:"This host is running Titan FTP Server and is prone to directory
  traversal vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to download
  arbitrary files and deletion of arbitrary files on the server.");

  script_tag(name:"affected", value:"Titan FTP Server version 8.10.1125 and prior");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("ftp_func.inc");

titanVer = get_kb_item("TitanFTP/Server/Ver");
if(!titanVer){
  exit(0);
}

ftpPort = get_ftp_port(default:21);
if(version_is_less_equal(version:titanVer, test_version:"8.10.1125")){
  report = report_fixed_ver(installed_version:titanVer, fixed_version:"8.30.1231");
  security_message(port:ftpPort, data:report);
  exit(0);
}

exit(99);