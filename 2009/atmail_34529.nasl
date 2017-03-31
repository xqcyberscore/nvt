###############################################################################
# OpenVAS Vulnerability Test
# $Id: atmail_34529.nasl 4574 2016-11-18 13:36:58Z teissa $
#
# @Mail WebMail Email Body HTML Injection Vulnerability
#
# Authors
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

tag_summary = "@Mail and @Mail WebMail are prone to an HTML-injection vulnerability
  because the applications fail to properly sanitize user-supplied
  input before using it in dynamically generated content.

  Hostile HTML and script code may be injected into vulnerable
  sections of the application. When viewed, this code may be rendered
  in the browser of a user viewing a malicious site.";


SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100149";
CPE = "cpe:/a:atmail:atmail";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version("$Revision: 4574 $");
 script_tag(name:"last_modification", value:"$Date: 2016-11-18 14:36:58 +0100 (Fri, 18 Nov 2016) $");
 script_tag(name:"creation_date", value:"2009-04-17 18:35:24 +0200 (Fri, 17 Apr 2009)");
 script_bugtraq_id(34529);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

 script_name("@Mail WebMail Email Body HTML Injection Vulnerability");


 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("atmail_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_mandatory_keys("Atmail/installed");
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/34529");
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);

if(!get_port_state(port))exit(0);

if(!vers = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

  if(!isnull(vers) && vers >!< "unknown") {

       if(version_is_equal(version:vers, test_version:"5.6"))
       {    
  	  security_message(port:port);
	  exit(0);
       }
  }


exit(0);
