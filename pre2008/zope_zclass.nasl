# OpenVAS Vulnerability Test
# $Id: zope_zclass.nasl 5390 2017-02-21 18:39:27Z mime $
# Description: Zope ZClass Permission Mapping Bug
#
# Authors:
# Georges Dagousset <georges.dagousset@alert4web.com>
#
# Copyright:
# Copyright (C) 2001 Alert4Web.com
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
#

tag_summary = "The remote web server contains an application server that is prone
to a privilege escalation flaw.

Description :

The remote web server uses a version of Zope which is older than
version 2.3.3.  In such versions, any user can visit a ZClass
declaration and change the ZClass permission mappings for methods and
other objects defined within the ZClass, possibly allowing for
unauthorized access within the Zope instance. 

*** OpenVAS solely relied on the version number of your server, so if 
*** the hotfix has already been applied, this might be a false positive";

tag_solution = "Upgrade to Zope 2.3.3 or apply the hotfix referenced in the vendor
advisory above.";

if(description)
{
 script_id(10777);
 script_version("$Revision: 5390 $");
 script_tag(name:"last_modification", value:"$Date: 2017-02-21 19:39:27 +0100 (Tue, 21 Feb 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"4.6");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2001-0567");
 
 name = "Zope ZClass Permission Mapping Bug";
 script_name(name);
 
 summary = "Checks Zope version";
 script_summary(summary);
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 script_copyright("This script is Copyright (C) 2001 Alert4Web.com");
 family = "Web Servers";
 script_family(family);
 script_dependencies("gb_get_http_banner.nasl");
 script_mandatory_keys("zope/banner");
 script_require_ports("Services/www", 80);
 script_require_keys("www/zope");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.zope.org/Products/Zope/Hotfix_2001-05-01/security_alert");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");


port = get_http_port(default:80);

banner = get_http_banner(port:port);

if(banner)
{
  if(egrep(pattern:"Server: .*Zope 2\.((0\..*)|(1\..*)|(2\..*)|(3\.[0-2]))", 
  		string:banner))
     security_message(port);
}
