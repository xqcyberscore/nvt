##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_titan_ftp_server_dir_trav_vuln.nasl 8187 2017-12-20 07:30:09Z teissa $
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

tag_impact = "Successful exploitation will allow attackers to download
arbitrary files and deletion of arbitrary files on the server.

Impact Level: Application.";

tag_affected = "Titan FTP Server version 8.10.1125 and prior";

tag_insight = "The flaws are due to
- Input validation error when processing 'XCRC' commands, which can be
exploited to determine the existence of a file outside the FTP root
directory.
- Input validation error when processing 'COMB' commands, which can be
exploited to read and delete an arbitrary file.";

tag_solution = "Upgrade to Titan FTP Server 8.30.1231 or later
For updates refer to http://www.titanftp.com/index.html";

tag_summary = "This host is running Titan FTP Server and is prone to directory
traversal vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902087");
  script_version("$Revision: 8187 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-20 08:30:09 +0100 (Wed, 20 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-07-02 08:02:13 +0200 (Fri, 02 Jul 2010)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_cve_id("CVE-2010-2425", "CVE-2010-2426");
  script_bugtraq_id(40949, 40904);
  script_name("Titan FTP Server 'XCRC' and 'COMB' Directory Traversal Vulnerabilities");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/40237");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/59492");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/511839/100/0/threaded");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("gb_titan_ftp_detect.nasl", "find_service.nasl");
  script_require_keys("TitanFTP/Server/Ver");
  script_require_ports("Services/ftp", 21);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  exit(0);
}

include("ftp_func.inc");
include("version_func.inc");

ftpPort = get_kb_item("Services/ftp");
if(!ftpPort){
  exit(0);
}

titanVer = get_kb_item("TitanFTP/Server/Ver");
if(!titanVer){
  exit(0);
}

# Grep for TitanFTP Server version 8.10.1125 and prior.
if(version_is_less_equal(version:titanVer, test_version:"8.10.1125")){
  security_message(ftpPort);
}
