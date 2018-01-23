###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ws_ftp_pro_client_format_string_vuln.nasl 8485 2018-01-22 07:57:57Z teissa $
#
# Ipswitch WS_FTP Professional 'HTTP' Response Format String Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

tag_impact = "Successful exploitation will allow attacker to execute arbitrary code in
  the context of the vulnerable application, failed exploit attempts will likely
  result in a denial-of-service condition.";
tag_affected = "WS_FTP Professional version prior to 12.2";
tag_insight = "The flaw is due to error in 'formatted-printing()' function. It fails to
  properly sanitize user supplied input before passing it as the format
  specifier. Specifically, the issue presents itself when the client parses
  specially crafted responses for a malicious HTTP server.";
tag_solution = "Upgrade to WS_FTP Professional version 12.2,
  For updates refer to http://www.ipswitchft.com/Individual/Products/Ws_Ftp_Pro/";
tag_summary = "This host is installed with WS_FTP professinal client and is prone to
  format string vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902171");
  script_version("$Revision: 8485 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-22 08:57:57 +0100 (Mon, 22 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-04-23 17:57:39 +0200 (Fri, 23 Apr 2010)");
  script_cve_id("CVE-2009-4775");
  script_bugtraq_id(36297);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_name("Ipswitch WS_FTP Professional 'HTTP' Response Format String Vulnerability");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/9607");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/53098");
  script_xref(name : "URL" , value : "http://www.juniper.net/security/auto/vulnerabilities/vuln36297.html");
  script_xref(name : "URL" , value : "http://www.packetstormsecurity.org/0909-exploits/nocoolnameforawsftppoc.pl.txt");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("FTP");
  script_dependencies("secpod_ws_ftp_client_detect.nasl");
  script_require_keys("Ipswitch/WS_FTP_Pro/Client/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

wsftpVer = get_kb_item("Ipswitch/WS_FTP_Pro/Client/Ver");
if(isnull(wsftpVer)){
  exit(0);
}

# Check WS_FTP Version less than 12.2
if(version_is_less(version:wsftpVer, test_version:"12.2")){
  security_message(0);
}
