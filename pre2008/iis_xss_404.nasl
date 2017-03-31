###############################################################################
# OpenVAS Vulnerability Test
# $Id: iis_xss_404.nasl 4703 2016-12-07 13:45:38Z cfi $
#
# IIS XSS via 404 error
#
# Authors:
# Matt Moore <matt.moore@westpoint.ltd.uk>
# www.westpoint.ltd.uk
#
# Copyright:
# Copyright (C) 2002 Matt Moore
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
###############################################################################

# admins who installed this patch would necessarily not be vulnerable to CVE-2001-1325

CPE = "cpe:/a:microsoft:iis";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10936");
  script_version("$Revision: 4703 $");
  script_tag(name:"last_modification", value:"$Date: 2016-12-07 14:45:38 +0100 (Wed, 07 Dec 2016) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_bugtraq_id(4476, 4483, 4486);
  script_name("IIS XSS via 404 error");
  script_cve_id("CVE-2002-0148", "CVE-2002-0150");     # lots of bugs rolled into one patch...
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2002 Matt Moore");
  script_family("Web application abuses");
  script_dependencies("secpod_ms_iis_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("IIS/installed");

  script_xref(name:"IAVA", value:"2002-A-0002");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/MS02-018.mspx");
  script_xref(name:"URL", value:"http://jscript.dk/adv/TL001/");

  tag_summary = "This IIS Server appears to vulnerable to one of the cross site scripting
  attacks described in MS02-018. The default '404' file returned by IIS uses scripting to output a link to
  top level domain part of the url requested. By crafting a particular URL it is possible to insert arbitrary script into the
  page for execution.

  The presence of this vulnerability also indicates that you are vulnerable to the other issues identified in MS02-018 (various remote buffer overflow and cross site scripting attacks...)";

  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

# Check makes a request for non-existent HTML file. The server should return a 404 for this request.
# The unpatched server returns a page containing the buggy JavaScript, on a patched server this has been
# updated to further check the input...

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 ); # To have a reference to the detection NVT

banner = get_http_banner( port:port );
if( "Microsoft-IIS" >!< banner ) exit( 0 );

req = http_get( item:"/blah.htm", port:port );
r = http_keepalive_send_recv( port:port, data:req );
if( ! r ) exit( 0 );

str1 = "urlresult";
str2 = "+ displayresult +";

if( ( str1 >< r ) && ( str2 >< r ) ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );
