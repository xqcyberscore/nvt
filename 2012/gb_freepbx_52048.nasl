###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_freepbx_52048.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# FreePBX 'gen_amp_conf.php' Credentials Information Disclosure Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_summary = "FreePBX is prone to an information-disclosure vulnerability that may
expose administrator's credentials.

Successful exploits will allow unauthenticated attackers to obtain
sensitive information that may aid in further attacks.";

tag_solution = "Report indicates that this issue has been fixed. Please contact the
vendor for more information.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103428");
 script_bugtraq_id(52048);
 script_version ("$Revision: 9352 $");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_name("FreePBX 'gen_amp_conf.php' Credentials Information Disclosure Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/52048");
 script_xref(name : "URL" , value : "http://www.freepbx.org/");
 script_xref(name : "URL" , value : "http://www.freepbx.org/forum/freepbx/development/security-gen-amp-conf-php");

 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-02-16 16:59:07 +0100 (Thu, 16 Feb 2012)");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("gb_freepbx_detect.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("freepbx/installed");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("version_func.inc");
   
port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

if(!dir = get_dir_from_kb(port:port,app:"freepbx"))exit(0);

url = string(dir, "/admin/modules/framework/bin/gen_amp_conf.php"); 

if(http_vuln_check(port:port, url:url,pattern:"ARI_ADMIN_USERNAME",extra_check:make_list("ARI_ADMIN_PASSWORD","AMPENGINE","DIE_FREEPBX_VERBOSE"))) {
     
  security_message(port:port);
  exit(0);

}

exit(0);

