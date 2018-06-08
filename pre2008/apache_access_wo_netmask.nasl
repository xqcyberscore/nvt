###############################################################################
# OpenVAS Vulnerability Test
# $Id: apache_access_wo_netmask.nasl 10121 2018-06-07 12:44:05Z cfischer $
#
# Description: Apache mod_access rule bypass
#
# Authors:
# George A. Theall, <theall@tifaware.com>.
#
# Copyright:
# Copyright (C) 2004 George A. Theall
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14177");
  script_version("$Revision: 10121 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-07 14:44:05 +0200 (Thu, 07 Jun 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(9829);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2003-0993");
  script_name("Apache mod_access rule bypass");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 George A. Theall");
  script_family("Web Servers");
  script_dependencies("find_service.nasl", "global_settings.nasl", "http_version.nasl", "gather-package-list.nasl");
  script_mandatory_keys("www/apache");
  script_require_ports("Services/www", 80);

  script_xref(name:"GLSA", value:"GLSA 200405-22");
  script_xref(name:"MDKSA", value:"MDKSA-2004:046");
  script_xref(name:"OpenPKG-SA", value:"OpenPKG-SA-2004.021-apache");
  script_xref(name:"SSA", value:"SSA:2004-133-01");
  script_xref(name:"TSLSA", value:"TSLSA-2004-0027");

  script_tag(name:"solution", value:"Upgrade to Apache version 1.3.31 or newer.");

  script_tag(name:"summary", value:"The target is running an Apache web server that may not properly handle
access controls. In effect, on big-endian 64-bit platforms, Apache
fails to match allow or deny rules containing an IP address but not a
netmask.

*****  OpenVAS has determined the vulnerability exists only by looking at

*****  the Server header returned by the web server running on the target.

*****  If the target is not a big-endian 64-bit platform, consider this a

*****  false positive.

Additional information on the vulnerability can be found at :

  - http://www.apacheweek.com/features/security-13

  - http://marc.theaimsgroup.com/?l=apache-cvs&m=107869603013722

  - http://nagoya.apache.org/bugzilla/show_bug.cgi?id=23850");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("global_settings.inc");
include("http_func.inc");

uname = get_kb_item("ssh/login/uname");
if( uname ){
  if( egrep(pattern:"i.86", string:uname) ) exit(0);
}

port = get_http_port(default:80);
host = http_host_name(port:port);

banner = get_http_banner(port:port);
if(!banner) exit(0);

sig = strstr(banner, "Server:");
if(!sig) exit(0);

if(ereg(pattern:"^Server:.*Apache(-AdvancedExtranetServer)?/1\.([0-2]\.[0-9]|3\.([0-9][^0-9]|[0-2][0-9]))", string:sig)) {
  security_message(port:port);
  exit(0);
}
