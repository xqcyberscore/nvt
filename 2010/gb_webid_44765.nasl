###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_webid_44765.nasl 7577 2017-10-26 10:41:56Z cfischer $
#
# WeBid Multiple Input Validation Vulnerabilities
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

tag_summary = "WeBid is prone to multiple input-validation vulnerabilities because it
fails to adequately sanitize user-supplied input. These
vulnerabilities include a local file-include vulnerability and a cross-site-
scripting vulnerability.

Exploiting these issues can allow an attacker to execute arbitrary
script code in the browser of an unsuspecting user in the context of
the affected site, obtain potentially sensitive information, and
execute arbitrary local scripts in the context of the webserver
process. This may allow the attacker to compromise the application and
the computer; other attacks are also possible.

WeBid 0.85P1 is vulnerable; other versions may be affected.";


SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100903";
CPE = "cpe:/a:webidsupport:webid";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version("$Revision: 7577 $");
 script_tag(name:"last_modification", value:"$Date: 2017-10-26 12:41:56 +0200 (Thu, 26 Oct 2017) $");
 script_tag(name:"creation_date", value:"2010-11-11 13:24:47 +0100 (Thu, 11 Nov 2010)");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2010-4873");
 script_bugtraq_id(44765);

 script_name("WeBid Multiple Input Validation Vulnerabilities");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/44765");
 script_xref(name : "URL" , value : "http://www.johnleitch.net/Vulnerabilities/WeBid.0.8.5P1.Reflected.Cross-site.Scripting/62");
 script_xref(name : "URL" , value : "http://www.webidsupport.com/");
 script_xref(name : "URL" , value : "http://www.johnleitch.net/Vulnerabilities/WeBid.0.8.5P1.Local.File.Inclusion/63");

 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_webid_detect.nasl", "os_detection.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("webid/installed");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("version_func.inc");
   
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!get_port_state(port))exit(0);

if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

files = traversal_files();

foreach file (keys(files)) {

  url = string(dir, "/active_auctions.php?lan=",crap(data:"../",length:3*9),files[file],"%00"); 

  if(http_vuln_check(port:port, url:url,pattern:file)) {
     
    security_message(port:port);
    exit(0);

  }
}

exit(0);
