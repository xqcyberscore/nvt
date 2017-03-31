###############################################################################
# OpenVAS Vulnerability Test
# $Id: phpbb_3_0_4.nasl 5016 2017-01-17 09:06:21Z teissa $
#
# phpBB 'ucp.php' Cross Site Scripting Vulnerability
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

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100035");
 script_version("$Revision: 5016 $");
 script_tag(name:"last_modification", value:"$Date: 2017-01-17 10:06:21 +0100 (Tue, 17 Jan 2017) $");
 script_tag(name:"creation_date", value:"2009-03-10 08:40:52 +0100 (Tue, 10 Mar 2009)");
 script_bugtraq_id(33995);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

 script_name("phpBB 'ucp.php' Cross Site Scripting Vulnerability");

 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("phpbb_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 script_tag(name : "solution" , value : "Upgrade to newer Version if available.");
 script_tag(name : "impact" , value : "An attacker may leverage this issue to execute arbitrary script code in the
 browser of an unsuspecting user in the context of the affected site. This may
 allow the attacker to steal cookie-based authentication credentials and to
 launch other attacks.");
 script_tag(name : "affected" , value : "This issue affects phpBB 3.x; other versions may also be affected.");
 script_tag(name : "summary" , value : "According to its version number, the remote version of phpbb
 is prone to a cross-site scripting vulnerability because it fails to sufficiently sanitize user-supplied data.

 UPDATE (March 13, 2009): The referenced BID is being retired because the issue cannot be exploited as described.");

 script_tag(name:"deprecated", value:TRUE); 

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/33995");
 script_xref(name : "URL" , value : "http://www.phpbb.com/");

 script_tag(name: "qod_type", value: "remote_banner");


 exit(0);
}

exit(66);

include("global_settings.inc");
include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);

install = get_kb_item(string("www/", port, "/phpBB"));
if (isnull(install)) exit(0);

if(vers = get_version_from_kb(port:port,app:"phpBB")) {

  if(version_is_less(version: vers, test_version: "3.0.5")) {
      security_message(port:port);
      exit(0);
  }

}

exit(99);