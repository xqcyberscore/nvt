###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_50639.nasl 5424 2017-02-25 16:52:36Z teissa $
#
# Apache HTTP Server 'ap_pregsub()' Function Local Denial of Service Vulnerability
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

tag_summary = "Apache HTTP Server is prone to a local denial-of-service
vulnerability because of a NULL-pointer dereference error or a
memory exhaustion.

Local attackers can exploit this issue to trigger a NULL-pointer
dereference or memory exhaustion, and cause a server crash, denying
service to legitimate users.

Note: To trigger this issue, 'mod_setenvif' must be enabled and the
      attacker should be able to place a malicious '.htaccess' file on
      the affected webserver.

Apache HTTP Server 2.0.x through 2.0.64 and 2.2.x through 2.2.21 are
vulnerable. Other versions may also be affected.";


if (description)
{
 script_id(103333);
 script_bugtraq_id(50639);
 script_cve_id("CVE-2011-4415");
 script_tag(name:"cvss_base", value:"1.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:N/I:N/A:P");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");
 script_version ("$Revision: 5424 $");

 script_name("Apache HTTP Server 'ap_pregsub()' Function Local Denial of Service Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/50639");
 script_xref(name : "URL" , value : "http://httpd.apache.org/");
 script_xref(name : "URL" , value : "http://www.halfdog.net/Security/2011/ApacheModSetEnvIfIntegerOverflow/");
 script_xref(name : "URL" , value : "http://www.gossamer-threads.com/lists/apache/dev/403775");

 script_tag(name:"last_modification", value:"$Date: 2017-02-25 17:52:36 +0100 (Sat, 25 Feb 2017) $");
 script_tag(name:"creation_date", value:"2011-11-15 12:33:51 +0100 (Tue, 15 Nov 2011)");
 script_category(ACT_GATHER_INFO);
 script_family("Web Servers");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("http_version.nasl", "secpod_apache_detect.nasl");
 script_require_ports("Services/www", 80);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("version_func.inc");
include("global_settings.inc");

httpdPort = get_http_port(default:80);
if(!httpdPort){
    exit(0);
}

version = get_kb_item("www/" + httpdPort + "/Apache");

if(version != NULL){

  if(version_in_range(version:version, test_version:"2.0",test_version2:"2.0.64") ||
     version_in_range(version:version, test_version:"2.2",test_version2:"2.2.21")) {
       security_message(port:httpdPort);
       exit(0);
  }

}

exit(0);
