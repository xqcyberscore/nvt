###############################################################################
# OpenVAS Vulnerability Test
# $Id: ipswitch_IMail_version.nasl 6695 2017-07-12 11:17:53Z cfischer $
#
# IMail account hijack
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2003 Michel Arboi
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

# References:
#
# http://cert.uni-stuttgart.de/archive/bugtraq/2001/10/msg00082.html
#
# Date:  Sun, 10 Mar 2002 21:37:33 +0100
# From: "Obscure" <obscure@eyeonsecurity.net>
# To: bugtraq@securityfocus.com, vulnwatch@vulnwatch.org
# Subject: IMail Account hijack through the Web Interface
#
#  Date:  Mon, 11 Mar 2002 04:11:43 +0000 (GMT)
# From: "Zillion" <zillion@safemode.org>
# To: "Obscure" <obscure@zero6.net>
# CC: bugtraq@securityfocus.com, vulnwatch@vulnwatch.org, "Obscure" <obscure@eyeonsecurity.net>
# Subject: Re: IMail Account hijack through the Web Interface

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11271");
  script_version("$Revision: 6695 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-12 13:17:53 +0200 (Wed, 12 Jul 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("IMail account hijack");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2003 Michel Arboi");
  script_family("Web Servers");
  script_dependencies("gb_get_http_banner.nasl", "no404.nasl");
  script_mandatory_keys("Ipswitch/banner");
  script_require_ports("Services/www", 80);

  tag_summary = "The remote host is running IMail web interface. In this version,
  the session is maintained via the URL. It will be disclosed in the Referer field
  if you receive an email with external links (e.g. images)";

  tag_solution = "Upgrade to IMail 7.06 or turn off the 'ignore source address in
  security check' option.";

  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");

port = get_http_port( default:80 );

banner = get_http_banner( port:port );
if( ! banner ) exit( 0 );

serv = egrep( string:banner, pattern:"^Server:.*");
if( ereg( pattern:"^Server:.*Ipswitch-IMail/(([1-6]\.)|(7\.0[0-5]))", string:serv ) ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );
